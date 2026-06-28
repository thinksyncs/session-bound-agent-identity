// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const StopWaitTime = 5 * time.Second

// Server is the common runtime server lifecycle interface.
type Server interface {
	Start() error
	Stop() error
}

// Config contains common TCP server configuration.
type Config struct {
	Host              string        `env:"HOST"                       envDefault:"localhost"`
	Port              string        `env:"PORT"                       envDefault:""`
	CertFile          string        `env:"SERVER_CERT"                envDefault:""`
	KeyFile           string        `env:"SERVER_KEY"                 envDefault:""`
	ServerCAFile      string        `env:"SERVER_CA_CERTS"            envDefault:""`
	ClientCAFile      string        `env:"CLIENT_CA_CERTS"            envDefault:""`
	ReadTimeout       time.Duration `env:"SERVER_READ_TIMEOUT"        envDefault:"15s"`
	WriteTimeout      time.Duration `env:"SERVER_WRITE_TIMEOUT"       envDefault:"15s"`
	ReadHeaderTimeout time.Duration `env:"SERVER_READ_HEADER_TIMEOUT" envDefault:"5s"`
	IdleTimeout       time.Duration `env:"SERVER_IDLE_TIMEOUT"        envDefault:"60s"`
	MaxHeaderBytes    int           `env:"SERVER_MAX_HEADER_BYTES"    envDefault:"1048576"`
}

// Base contains shared server fields.
type Base struct {
	Ctx     context.Context
	Cancel  context.CancelFunc
	Name    string
	Address string
	Config  Config
	Logger  *slog.Logger
}

func NewBase(ctx context.Context, cancel context.CancelFunc, name string, config Config, logger *slog.Logger) Base {
	return Base{
		Ctx:     ctx,
		Cancel:  cancel,
		Name:    name,
		Address: fmt.Sprintf("%s:%s", config.Host, config.Port),
		Config:  config,
		Logger:  logger,
	}
}

// StopSignalHandler stops all servers on SIGINT or SIGABRT.
func StopSignalHandler(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger, svcName string, servers ...Server) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGABRT)
	defer signal.Stop(signals)

	select {
	case sig := <-signals:
		defer cancel()
		err := stopAll(servers...)
		if err != nil {
			logger.Error(fmt.Sprintf("%s service error during shutdown: %v", svcName, err))
		}
		logger.Info(fmt.Sprintf("%s service shutdown by signal: %s", svcName, sig))
		return err
	case <-ctx.Done():
		return nil
	}
}

func stopAll(servers ...Server) error {
	var out error
	for _, srv := range servers {
		if err := srv.Stop(); err != nil {
			if out == nil {
				out = err
			} else {
				out = fmt.Errorf("%v; %w", out, err)
			}
		}
	}
	return out
}

func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	cert, err := readFileOrData(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read certificate: %w", err)
	}
	key, err := readFileOrData(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read private key: %w", err)
	}
	return tls.X509KeyPair(cert, key)
}

func LoadRootCACerts(input string) (*x509.CertPool, error) {
	pemData, err := readFileOrData(input)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA data: %w", err)
	}
	if len(pemData) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("failed to append root CA certificate")
	}
	return pool, nil
}

func readFileOrData(input string) ([]byte, error) {
	if _, err := os.Stat(input); err == nil {
		return os.ReadFile(input)
	}
	return []byte(input), nil
}
