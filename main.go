package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	_ "go.uber.org/automaxprocs"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/server"
	"github.com/crtsh/ctsubmit/submitter"
)

func main() {
	// Load configuration and initialize the logger. config.Load is the single source of configuration; the result is injected into everything below.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	lgr, err := logger.InitLogger(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	config.LogStartupInfo(lgr)

	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer lgr.Info("Shutting down")
	defer logger.ShutdownWG.Wait()

	// Start the HTTP servers (Web and Monitoring) immediately.
	// Readiness probes will report "not ready" until initial data is loaded.
	mon := monitor.New(cfg, lgr)
	sub := submitter.New(cfg, lgr, mon)
	h := health.New()
	server.Run(cfg, sub, mon, h, lgr)
	defer server.Shutdown(lgr)

	// Start the various goroutines.
	logger.ShutdownWG.Add(2)
	go mon.UptimeFetcher(ctx)
	go mon.STHMonitor(ctx)

	// Perform initial data fetches asynchronously, then mark the service as ready.
	go func() {
		mon.FetchEndpointUptimes()
		mon.FetchAllSTHs()
		h.SetInitialDataReady()
		lgr.Info("Initial external data loaded; service is now ready")
	}()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	_ = lgr.Sync()
}
