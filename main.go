package main

import (
	"context"
	"os/signal"
	"syscall"

	_ "go.uber.org/automaxprocs"

	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/server"
)

func main() {
	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer logger.Logger.Info("Shutting down")
	defer logger.ShutdownWG.Wait()

	// Start the HTTP servers (Web and Monitoring) immediately.
	// Readiness probes will report "not ready" until initial data is loaded.
	server.Run()
	defer server.Shutdown()

	// Start the various goroutines.
	logger.ShutdownWG.Add(2)
	go monitor.UptimeFetcher(ctx)
	go monitor.STHMonitor(ctx)

	// Perform initial data fetches asynchronously, then mark the service as ready.
	go func() {
		monitor.FetchEndpointUptimes()
		monitor.FetchAllSTHs()
		health.SetInitialDataReady()
		logger.Logger.Info("Initial external data loaded; service is now ready")
	}()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	_ = logger.Logger.Sync()
}
