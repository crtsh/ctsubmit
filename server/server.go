package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/request"
	"github.com/crtsh/ctsubmit/submitter"
	"github.com/crtsh/ctsubmit/utils"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

var webServer *fasthttp.Server
var webRequestLatency prometheus.Summary

func webHandler(fhctx *fasthttp.RequestCtx, cfg *config.Settings, sub *submitter.Submitter, mon *monitor.Monitor, h *health.Health, log *zap.Logger) {
	endpointPath := strings.ToLower(utils.B2S(fhctx.Path())[1:])

	if fhctx.IsGet() {
		switch endpointPath {
		case endpoint.ENDPOINTSTRING_CSS:
			request.CSS(fhctx)
		case endpoint.ENDPOINTSTRING_DASHBOARD:
			request.Dashboard(fhctx, cfg, mon)
		case endpoint.ENDPOINTSTRING_FAVICON:
			favicon(fhctx)
		case endpoint.ENDPOINTSTRING_FRONTPAGE:
			request.FrontPage(fhctx)
		case endpoint.ENDPOINTSTRING_MASCOT:
			mascot(fhctx)
		case endpoint.ENDPOINTSTRING_USABLETLSLOGS:
			request.LogList(fhctx, loglists.UsableTLSLogs, "Usable TLS Logs")
		case endpoint.ENDPOINTSTRING_ACTIVETLSLOGS:
			request.LogList(fhctx, loglists.ActiveTLSLogs, "Active TLS Logs")
		case endpoint.ENDPOINTSTRING_TESTTLSLOGS:
			request.LogList(fhctx, loglists.TestTLSLogs, "Test TLS Logs")
		case endpoint.ENDPOINTSTRING_USABLEBIMILOGS:
			request.LogList(fhctx, loglists.UsableBIMILogs, "Usable BIMI Logs")
		case endpoint.ENDPOINTSTRING_ADDCHAIN, endpoint.ENDPOINTSTRING_ADDPRECHAIN:
			request.APIWebpage(fhctx, endpointPath)
		default:
			fhctx.NotFound()
			logger.SetDetails(fhctx, zap.InfoLevel, "Invalid endpoint", nil, nil)
		}

	} else if fhctx.IsPost() {
		if request.POST(fhctx, endpointPath, cfg, sub, h) == -1 {
			// Request timed out.
			fhctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			fhctx.SetContentType("text/plain")
			logger.SetDetails(fhctx, zap.InfoLevel, "Request timeout", nil, nil)
			defer fhctx.TimeoutErrorWithResponse(&fhctx.Response) // The logger needs to run first.
		}

	} else {
		fhctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		logger.SetDetails(fhctx, zap.InfoLevel, "Method not allowed", nil, nil)
	}

	logger.LogRequest(log, fhctx)
	webRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

var monitoringServer *fasthttp.Server
var monitoringRequestLatency prometheus.Summary

func monitoringHandler(fhctx *fasthttp.RequestCtx, cfg *config.Settings, mon *monitor.Monitor, h *health.Health, log *zap.Logger) {
	status := 0
	switch strings.ToLower(utils.B2S(fhctx.Path())[1:]) {
	case endpoint.ENDPOINTSTRING_CSS:
		request.CSS(fhctx)
	case endpoint.ENDPOINTSTRING_DASHBOARD:
		request.Dashboard(fhctx, cfg, mon)
	case endpoint.ENDPOINTSTRING_FAVICON:
		favicon(fhctx)
	case endpoint.ENDPOINTSTRING_MASCOT:
		mascot(fhctx)
	case endpoint.ENDPOINTSTRING_LIVEZ:
		status = livez(fhctx, cfg, h)
	case endpoint.ENDPOINTSTRING_READYZ:
		status = readyz(fhctx, cfg, h)
	case endpoint.ENDPOINTSTRING_METRICS:
		status = metrics(fhctx, cfg)
	case endpoint.ENDPOINTSTRING_BUILD:
		if cfg.Server.EnableDebugEndpoints {
			buildInfo(fhctx)
		} else {
			fhctx.NotFound()
		}
	case endpoint.ENDPOINTSTRING_CONFIG:
		if cfg.Server.EnableDebugEndpoints {
			configInfo(fhctx, cfg)
		} else {
			fhctx.NotFound()
		}
	default:
		if cfg.Server.EnableDebugEndpoints && profilingHandler(fhctx) {
			// Handled by pprof.
		} else {
			fhctx.NotFound()
		}
	}

	if status == -1 { // Request timed out.
		fhctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
		fhctx.SetContentType("text/plain")
		if !fhctx.IsHead() {
			fhctx.SetBody(utils.S2B("ERROR"))
		}
		logger.SetDetails(fhctx, zap.WarnLevel, "Monitoring timeout", nil, nil)
		defer fhctx.TimeoutErrorWithResponse(&fhctx.Response) // The logger needs to run first.
	}

	logger.LogRequest(log, fhctx)
	monitoringRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

func Run(cfg *config.Settings, sub *submitter.Submitter, mon *monitor.Monitor, h *health.Health, log *zap.Logger) {
	webServer = &fasthttp.Server{
		Handler:               func(fhctx *fasthttp.RequestCtx) { webHandler(fhctx, cfg, sub, mon, h, log) },
		CloseOnShutdown:       true,
		ReadTimeout:           cfg.Server.ReadTimeout,
		IdleTimeout:           cfg.Server.IdleTimeout,
		DisableKeepalive:      cfg.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if cfg.Server.WebserverPort != 0 {
		log.Info("Starting WebServer", zap.Int("port", cfg.Server.WebserverPort))
		go func() {
			if err := webServer.ListenAndServe(fmt.Sprintf(":%d", cfg.Server.WebserverPort)); err != nil {
				log.Fatal("webServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if cfg.Server.WebserverPath != "" {
		log.Info("Starting WebServer", zap.String("path", cfg.Server.WebserverPath))
		go func() {
			if err := webServer.ListenAndServeUNIX(cfg.Server.WebserverPath, cfg.Server.SocketPermissions); err != nil {
				log.Fatal("webServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}

	monitoringServer = &fasthttp.Server{
		Handler:               func(fhctx *fasthttp.RequestCtx) { monitoringHandler(fhctx, cfg, mon, h, log) },
		CloseOnShutdown:       true,
		ReadTimeout:           cfg.Server.ReadTimeout,
		IdleTimeout:           cfg.Server.IdleTimeout,
		DisableKeepalive:      cfg.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if cfg.Server.MonitoringPort != 0 {
		listenAddr := fmt.Sprintf("%s:%d", cfg.Server.MonitoringAddress, cfg.Server.MonitoringPort)
		if cfg.Server.MonitoringAddress == "" || cfg.Server.MonitoringAddress == "0.0.0.0" {
			log.Warn("MonitoringServer is binding to all interfaces; set server.monitoringAddress (e.g. \"127.0.0.1\") to restrict access in hardened/sidecar deployments", zap.Int("port", cfg.Server.MonitoringPort))
		}
		log.Info("Starting MonitoringServer", zap.String("address", listenAddr))
		go func() {
			if err := monitoringServer.ListenAndServe(listenAddr); err != nil {
				log.Fatal("monitoringServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if cfg.Server.MonitoringPath != "" {
		log.Info("Starting MonitoringServer", zap.String("path", cfg.Server.MonitoringPath))
		go func() {
			if err := monitoringServer.ListenAndServeUNIX(cfg.Server.MonitoringPath, cfg.Server.SocketPermissions); err != nil {
				log.Fatal("monitoringServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}
}

func Shutdown(log *zap.Logger) {
	log.Info("Stopping WebServer (gracefully)")
	if err := webServer.Shutdown(); err != nil {
		log.Error("webServer.Shutdown failed", zap.Error(err))
	}
	log.Info("Stopped WebServer")

	log.Info("Stopping MonitoringServer (gracefully)")
	if err := monitoringServer.Shutdown(); err != nil {
		log.Error("monitoringServer.Shutdown failed", zap.Error(err))
	}
	log.Info("Stopped MonitoringServer")
}
