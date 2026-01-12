package sslutil

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSSLHandshakeWithCertPool verifies the handshake succeeds with a custom cert pool.
func TestSSLHandshakeWithCertPool(t *testing.T) {
	// Start a local TLS server.
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Build a cert pool from the server certificate.
	certPool, err := buildCertPoolFromServer(server)
	if err != nil {
		t.Fatalf("failed to build cert pool: %v", err)
	}

	// Execute the TLS handshake.
	err = SSLHandshakeWithCertPool(server.Listener.Addr().String(), certPool)
	if err != nil {
		t.Fatalf("expected handshake to succeed: %v", err)
	}
}

// buildCertPoolFromServer creates a cert pool with the server certificate.
func buildCertPoolFromServer(server *httptest.Server) (*x509.CertPool, error) {
	// Parse the leaf certificate from the server config.
	certBytes := server.TLS.Certificates[0].Certificate[0]
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	// Create a cert pool and add the certificate.
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool, nil
}
