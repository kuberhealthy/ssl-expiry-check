package main

import (
	"context"
	"time"

	nodecheck "github.com/kuberhealthy/kuberhealthy/v3/pkg/nodecheck"
	log "github.com/sirupsen/logrus"
)

// main loads configuration and executes the SSL expiry check.
func main() {
	// Enable nodecheck debug output for parity with v2 behavior.
	nodecheck.EnableDebugOutput()

	// Parse configuration from environment variables.
	cfg, err := parseConfig()
	if err != nil {
		reportFailureAndExit(err)
		return
	}

	// Wait for the node to join the worker pool.
	nodeCheckTimeout := time.Minute * 1
	nodeCheckCtx, _ := context.WithTimeout(context.Background(), nodeCheckTimeout)
	waitForNodeToJoin(nodeCheckCtx)

	// Build the checker.
	checker := NewChecker(cfg)

	// Create a timeout context for the check.
	checkCtx, cancelFunc := context.WithTimeout(context.Background(), cfg.CheckTimeout)
	defer cancelFunc()

	// Run the check.
	err = checker.Run(checkCtx, cancelFunc)
	if err != nil {
		log.Errorln("Error completing SSL expiry check for", cfg.DomainName+":", err)
	}
}

// waitForNodeToJoin waits for the node to join the worker pool.
func waitForNodeToJoin(ctx context.Context) {
	// Check if Kuberhealthy is reachable.
	err := nodecheck.WaitForKuberhealthy(ctx)
	if err != nil {
		log.Errorln("Failed to reach Kuberhealthy:", err.Error())
	}
}
