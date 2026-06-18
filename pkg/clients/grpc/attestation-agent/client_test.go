// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation_agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	aa "github.com/thinksyncs/hardware-aware-tls-identity-binding/internal/proto/attestation-agent"
	"google.golang.org/grpc"
)

func unixSocketPath(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cocos-grpc-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

type mockAttestationAgentServer struct {
	aa.UnimplementedAttestationAgentServiceServer
	getTokenCalled bool
	lastTokenType  string
	tokenErr       error
	tokenResponse  []byte
}

func (m *mockAttestationAgentServer) GetToken(ctx context.Context, req *aa.GetTokenRequest) (*aa.GetTokenResponse, error) {
	m.getTokenCalled = true
	m.lastTokenType = req.TokenType
	if m.tokenErr != nil {
		return nil, m.tokenErr
	}
	return &aa.GetTokenResponse{Token: m.tokenResponse}, nil
}

func TestNewClientUnixSocket(t *testing.T) {
	socketPath := unixSocketPath(t, "aa-test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{tokenResponse: []byte("mock-token")}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}

func TestNewClientTCPAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{tokenResponse: []byte("mock-token")}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(listener.Addr().String())
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}

func TestGetToken(t *testing.T) {
	socketPath := unixSocketPath(t, "aa-gettoken.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{tokenResponse: []byte("kbs-token-response")}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	token, err := client.GetToken(ctx, "kbs")
	require.NoError(t, err)
	assert.Equal(t, []byte("kbs-token-response"), token)
	assert.True(t, mockServer.getTokenCalled)
	assert.Equal(t, "kbs", mockServer.lastTokenType)
}

func TestGetTokenError(t *testing.T) {
	socketPath := unixSocketPath(t, "aa-error.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{tokenErr: assert.AnError}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	token, err := client.GetToken(ctx, "kbs")
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "failed to get token from attestation-agent")
}

func TestGetTokenCanceledContext(t *testing.T) {
	socketPath := unixSocketPath(t, "aa-cancel.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{tokenResponse: []byte("token")}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = client.GetToken(ctx, "kbs")
	assert.Error(t, err)
}

func TestClientClose(t *testing.T) {
	socketPath := unixSocketPath(t, "aa-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockAttestationAgentServer{}
	aa.RegisterAttestationAgentServiceServer(grpcServer, mockServer)

	go func() { _ = grpcServer.Serve(listener) }()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

func TestClientInterface(t *testing.T) {
	var _ Client = (*client)(nil)
}
