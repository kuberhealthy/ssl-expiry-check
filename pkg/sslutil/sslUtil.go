package sslutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// TimeoutSeconds is the timeout for TLS connections.
	TimeoutSeconds = 10
)

// CertExpiry checks the certificate expiration for a host and port.
func CertExpiry(host string, port string, days string, overrideTLS bool) (bool, bool, error) {
	// Announce the check target.
	log.Infoln("Testing SSL expiration on host", host, "over port", port)

	// Track expiration state.
	certExpired := false
	expireWarning := false

	// Create a dialer with a timeout.
	dialer := &net.Dialer{
		Timeout: time.Duration(TimeoutSeconds) * time.Second,
	}

	// Connect to the host over TLS.
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, &tls.Config{
		InsecureSkipVerify: overrideTLS,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		log.Warnln([]*x509.Certificate{}, "", err)
		return certExpired, expireWarning, err
	}
	defer conn.Close()

	// Grab the certificate chain.
	cert := conn.ConnectionState().PeerCertificates
	currentTime := time.Now()

	// Convert the days string to an integer for comparisons.
	daysInt64, _ := strconv.ParseUint(days, 10, 64)
	daysInt := uint(daysInt64)

	// Calculate the days until the cert expires.
	daysUntilInvalid := uint(cert[0].NotAfter.Sub(currentTime).Hours()) / uint(24)
	log.Infoln("Certificate for", host, "is valid from", cert[0].NotBefore, "until", cert[0].NotAfter)

	// Check the certificate validity window.
	if currentTime.Before(cert[0].NotBefore) || currentTime.After(cert[0].NotAfter) {
		certExpired = true
		log.Warnln("Certificate for domain", host, "expired on", cert[0].NotAfter)
	}

	// Check for expiring soon status.
	if daysInt >= daysUntilInvalid {
		expireWarning = true
		log.Warnln("Certificate for domain", host, "will expire in", daysUntilInvalid, "days")
	}

	// Log a healthy certificate status.
	if daysInt <= daysUntilInvalid && (currentTime.Before(cert[0].NotAfter) || currentTime.After(cert[0].NotBefore)) {
		log.Infoln("Certificate for domain", host, "is currently valid and will expire in", daysUntilInvalid, "days")
	}

	return certExpired, expireWarning, err
}

// SSLHandshakeWithCertPool performs a TLS handshake with the specified cert pool.
func SSLHandshakeWithCertPool(urlHost string, certPool *x509.CertPool) error {
	// Create a dialer with a timeout.
	dialer := &net.Dialer{
		Timeout: time.Duration(TimeoutSeconds) * time.Second,
	}

	// Dial the TLS endpoint.
	conn, err := tls.DialWithDialer(dialer, "tcp", urlHost, &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		RootCAs:            certPool,
	})
	if err != nil {
		return fmt.Errorf("error making connection to perform TLS handshake: %w", err)
	}
	defer conn.Close()

	// Perform the handshake.
	err = conn.Handshake()
	if err != nil {
		return fmt.Errorf("unable to perform TLS handshake: %w", err)
	}

	return nil
}
