// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

// Proxy is an egress proxy server.
type Proxy struct {
	logger    *slog.Logger
	server    *http.Server
	addr      string
	transport *http.Transport
	policy    destinationPolicy
}

type ProxyOption func(*Proxy)

// WithAllowedDestinations adds explicit host, host:port, IP, or CIDR
// destinations. Loopback destinations are allowed by default.
func WithAllowedDestinations(entries []string) ProxyOption {
	return func(p *Proxy) {
		p.policy = newDestinationPolicy(entries)
	}
}

// NewProxy creates a new egress proxy. By default, only loopback destinations
// are allowed.
func NewProxy(logger *slog.Logger, addr string, opts ...ProxyOption) *Proxy {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: false},
		ForceAttemptHTTP2: true,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		logger.Warn("failed to configure HTTP/2 transport", "error", err)
	}

	p := &Proxy{
		logger:    logger,
		addr:      addr,
		transport: transport,
		policy:    newDestinationPolicy(nil),
	}
	for _, opt := range opts {
		opt(p)
	}
	p.server = &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(p.handle),
	}
	return p
}

// NewProxyWithAllowedDestinations creates a proxy with an explicit destination
// allowlist.
func NewProxyWithAllowedDestinations(logger *slog.Logger, addr string, entries []string) *Proxy {
	return NewProxy(logger, addr, WithAllowedDestinations(entries))
}

// Start starts the proxy server.
func (p *Proxy) Start() error {
	p.logger.Info("starting egress proxy", "addr", p.addr)
	return p.server.ListenAndServe()
}

// Stop stops the proxy server.
func (p *Proxy) Stop(ctx context.Context) error {
	p.logger.Info("stopping egress proxy")
	return p.server.Shutdown(ctx)
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	if r.ProtoMajor == 2 {
		p.handleHTTP2(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	p.logger.Info("CONNECT request received", "host", host)

	if !p.allowDestination(host, "https") {
		http.Error(w, "egress destination denied", http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		p.logger.Error("failed to dial destination", "host", host, "error", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("failed to hijack connection", "error", err)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		p.logger.Error("failed to send CONNECT response", "error", err)
		return
	}
	p.pipe(clientConn, destConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	targetURL := outboundURL(r)
	p.logger.Info("HTTP request", "method", r.Method, "url", targetURL.String())

	if !p.allowDestination(targetURL.Host, targetURL.Scheme) {
		http.Error(w, "egress destination denied", http.StatusForbidden)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.URL = targetURL
	outReq.Host = targetURL.Host
	outReq.RequestURI = ""
	delHopHeaders(outReq.Header)

	client := &http.Client{
		Transport: p.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(outReq)
	if err != nil {
		p.logger.Error("failed to execute request", "error", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		p.logger.Error("failed to copy response body", "error", err)
	}
}

func (p *Proxy) handleHTTP2(w http.ResponseWriter, r *http.Request) {
	targetURL := outboundURL(r)
	p.logger.Info("HTTP/2 request", "method", r.Method, "host", targetURL.Host, "path", targetURL.Path)

	if !p.allowDestination(targetURL.Host, targetURL.Scheme) {
		http.Error(w, "egress destination denied", http.StatusForbidden)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host
			if !r.URL.IsAbs() {
				req.URL.Path = r.URL.Path
				req.URL.RawQuery = r.URL.RawQuery
			}
			delHopHeaders(req.Header)
		},
		Transport: p.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.logger.Error("HTTP/2 proxy error", "error", err, "host", r.Host)
			http.Error(w, err.Error(), http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r)
}

func outboundURL(r *http.Request) *url.URL {
	targetURL := *r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}
	return &targetURL
}

func (p *Proxy) allowDestination(target, scheme string) bool {
	host, port, err := destinationParts(target, scheme)
	if err != nil {
		p.logger.Warn("invalid egress destination", "target", target, "error", err)
		return false
	}
	if p.policy.allowed(host, port) {
		return true
	}
	p.logger.Warn("egress destination denied", "host", host, "port", port)
	return false
}

func destinationParts(target, scheme string) (string, string, error) {
	if target == "" {
		return "", "", fmt.Errorf("missing host")
	}

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			host = strings.Trim(target, "[]")
			port = defaultPort(scheme)
		} else {
			return "", "", err
		}
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("missing host")
	}
	if port == "" {
		port = defaultPort(scheme)
	}
	return host, port, nil
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https":
		return "443"
	default:
		return "80"
	}
}

func (p *Proxy) pipe(src, dst net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		p.logger.Debug("pipe src->dst completed", "bytes", n, "error", err)
		if c, ok := dst.(*net.TCPConn); ok {
			if err := c.CloseWrite(); err != nil {
				p.logger.Debug("failed to close write end of dst", "error", err)
			}
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(src, dst)
		p.logger.Debug("pipe dst->src completed", "bytes", n, "error", err)
		if c, ok := src.(*net.TCPConn); ok {
			if err := c.CloseWrite(); err != nil {
				p.logger.Debug("failed to close write end of src", "error", err)
			}
		}
	}()

	wg.Wait()
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailers",
		"Transfer-Encoding",
		"Upgrade",
	} {
		header.Del(h)
	}
}

type destinationPolicy struct {
	allowLoopback bool
	hosts         map[string]struct{}
	hostPorts     map[string]struct{}
	prefixes      []netip.Prefix
}

func newDestinationPolicy(entries []string) destinationPolicy {
	policy := destinationPolicy{
		allowLoopback: true,
		hosts:         make(map[string]struct{}),
		hostPorts:     make(map[string]struct{}),
	}
	for _, entry := range entries {
		policy.add(entry)
	}
	return policy
}

func (p *destinationPolicy) add(entry string) {
	entry = strings.TrimSpace(strings.ToLower(entry))
	if entry == "" {
		return
	}
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		p.prefixes = append(p.prefixes, prefix)
		return
	}
	if addr, err := netip.ParseAddr(strings.Trim(entry, "[]")); err == nil {
		p.prefixes = append(p.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		return
	}
	if host, port, err := net.SplitHostPort(entry); err == nil {
		host = strings.Trim(strings.ToLower(host), "[]")
		p.hostPorts[net.JoinHostPort(host, port)] = struct{}{}
		return
	}
	p.hosts[strings.Trim(entry, "[]")] = struct{}{}
}

func (p destinationPolicy) allowed(host, port string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" && p.allowLoopback {
		return true
	}
	if _, ok := p.hostPorts[net.JoinHostPort(host, port)]; ok {
		return true
	}
	if _, ok := p.hosts[host]; ok {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	if addr.IsLoopback() && p.allowLoopback {
		return true
	}
	for _, prefix := range p.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
