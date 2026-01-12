package main

import (
	"context"
	"fmt"
	"time"

	"github.com/kuberhealthy/ssl-expiry-check/pkg/sslutil"
	log "github.com/sirupsen/logrus"
)

// Checker runs the SSL expiry check logic.
type Checker struct {
	// domainName is the domain to check.
	domainName string
	// portNum is the TLS port to check.
	portNum string
	// daysToExpire is the expiry threshold in days.
	daysToExpire string
	// insecureSkipVerify skips TLS verification when true.
	insecureSkipVerify bool
	// checkTimeout is the timeout for the check.
	checkTimeout time.Duration
}

// NewChecker creates a Checker from configuration.
func NewChecker(cfg *CheckConfig) *Checker {
	// Build the checker instance.
	return &Checker{
		domainName:         cfg.DomainName,
		portNum:            cfg.Port,
		daysToExpire:       cfg.DaysToExpire,
		insecureSkipVerify: cfg.InsecureSkipVerify,
		checkTimeout:       cfg.CheckTimeout,
	}
}

// Run executes the expiry check and reports success or failure.
func (sec *Checker) Run(ctx context.Context, cancel context.CancelFunc) error {
	// Start the async check routine.
	doneChan := make(chan error)
	runTimeout := time.After(sec.checkTimeout)

	go sec.runChecksAsync(doneChan)

	// Wait for timeout or completion.
	select {
	case <-ctx.Done():
		log.Infoln("Cancelling check and shutting down due to interrupt.")
		return reportFailure("Cancelling check and shutting down due to interrupt.")
	case <-runTimeout:
		cancel()
		log.Infoln("Cancelling check and shutting down due to timeout.")
		return reportFailure("Failed to complete SSL expiry check in time. Timeout was reached.")
	case err := <-doneChan:
		cancel()
		if err != nil {
			return reportFailure(err.Error())
		}
		return reportSuccess()
	}
}

// runChecksAsync executes the expiry check and sends the result.
func (sec *Checker) runChecksAsync(doneChan chan error) {
	// Perform the check and send the result.
	err := sec.doChecks()
	doneChan <- err
}

// doChecks runs the SSL expiration check.
func (sec *Checker) doChecks() error {
	// Check certificate expiration.
	certExpired, expirePending, err := sslutil.CertExpiry(sec.domainName, sec.portNum, sec.daysToExpire, sec.insecureSkipVerify)
	if err != nil {
		log.Errorln("Unable to perform SSL expiration check")
		return err
	}

	// Report an expired certificate.
	if certExpired {
		return fmt.Errorf("Certificate for domain %s is expired", sec.domainName)
	}

	// Report a soon-to-expire certificate.
	if expirePending {
		return fmt.Errorf("Certificate for domain %s is expiring in less than %s days", sec.domainName, sec.daysToExpire)
	}

	return nil
}
