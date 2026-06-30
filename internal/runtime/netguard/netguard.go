// Copyright (c) 2026 ToppyMicroServices OÜ
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net"
	"net/url"
	"strings"
)

// IsLoopbackHost reports whether host names a local-only endpoint.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if strings.EqualFold(host, "localhost") {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PlaintextBindAllowed reports whether a plaintext listener is local-only.
func PlaintextBindAllowed(host string) bool {
	return IsLoopbackHost(host)
}

// PlaintextTargetAllowed reports whether a plaintext client target is local-only.
func PlaintextTargetAllowed(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if strings.HasPrefix(target, "unix://") || strings.HasPrefix(target, "/") || strings.HasPrefix(target, ".") {
		return true
	}

	host := targetHost(target)
	return IsLoopbackHost(host)
}

// InsecureHTTPAllowed reports whether http:// transport is local-only.
func InsecureHTTPAllowed(rawURL url.URL) bool {
	return strings.EqualFold(rawURL.Scheme, "http") && IsLoopbackHost(rawURL.Hostname())
}

func targetHost(target string) string {
	if strings.Contains(target, "://") {
		parsed, err := url.Parse(target)
		if err != nil {
			return ""
		}
		if parsed.Host != "" {
			return hostOnly(parsed.Host)
		}
		if parsed.Opaque != "" {
			return hostOnly(parsed.Opaque)
		}
	}

	if beforeSlash, _, ok := strings.Cut(target, "/"); ok {
		target = beforeSlash
	}
	return hostOnly(target)
}

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return strings.Trim(hostport, "[]")
}
