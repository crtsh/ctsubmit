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
	// Load configuration and initialize the logger. config.Load is the single
	// source of configuration; the result is injected into everything below.
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	if err := logger.InitLogger(cfg.Logging.IsDevelopment, cfg.Logging.Level, cfg.Logging.SamplingInitial, cfg.Logging.SamplingThereafter); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	logger.XFFUseFirstIPAddress = cfg.Logging.XFFUseFirstIPAddress
	config.LogStartupInfo()

	// Configure graceful shutdown capabilities.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer logger.Logger.Info("Shutting down")
	defer logger.ShutdownWG.Wait()

	// Start the HTTP servers (Web and Monitoring) immediately.
	// Readiness probes will report "not ready" until initial data is loaded.
	mon := monitor.New(cfg)
	sub := submitter.New(cfg, logger.Logger, mon)
	server.Run(cfg, sub, mon)
	defer server.Shutdown()

	// Start the various goroutines.
	logger.ShutdownWG.Add(2)
	go mon.UptimeFetcher(ctx)
	go mon.STHMonitor(ctx)

	// Perform initial data fetches asynchronously, then mark the service as ready.
	go func() {
		mon.FetchEndpointUptimes()
		mon.FetchAllSTHs()
		health.SetInitialDataReady()
		logger.Logger.Info("Initial external data loaded; service is now ready")
	}()

	// Wait to be interrupted.
	<-ctx.Done()

	// Ensure all log messages are flushed before we exit.
	_ = logger.Logger.Sync()
}
