package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
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

func webHandler(fhctx *fasthttp.RequestCtx, sub *submitter.Submitter, mon *monitor.Monitor) {
	endpointPath := strings.ToLower(utils.B2S(fhctx.Path())[1:])

	if fhctx.IsGet() {
		switch endpointPath {
		case endpoint.ENDPOINTSTRING_CSS:
			request.CSS(fhctx)
		case endpoint.ENDPOINTSTRING_DASHBOARD:
			request.Dashboard(fhctx, mon)
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
		if request.POST(fhctx, endpointPath, sub) == -1 {
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

	logger.LogRequest(fhctx)
	webRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

var monitoringServer *fasthttp.Server
var monitoringRequestLatency prometheus.Summary

func monitoringHandler(fhctx *fasthttp.RequestCtx, mon *monitor.Monitor) {
	status := 0
	switch strings.ToLower(utils.B2S(fhctx.Path())[1:]) {
	case endpoint.ENDPOINTSTRING_CSS:
		request.CSS(fhctx)
	case endpoint.ENDPOINTSTRING_DASHBOARD:
		request.Dashboard(fhctx, mon)
	case endpoint.ENDPOINTSTRING_FAVICON:
		favicon(fhctx)
	case endpoint.ENDPOINTSTRING_MASCOT:
		mascot(fhctx)
	case endpoint.ENDPOINTSTRING_LIVEZ:
		status = livez(fhctx)
	case endpoint.ENDPOINTSTRING_READYZ:
		status = readyz(fhctx)
	case endpoint.ENDPOINTSTRING_METRICS:
		status = metrics(fhctx)
	case endpoint.ENDPOINTSTRING_BUILD:
		if config.Config.Server.EnableDebugEndpoints {
			buildInfo(fhctx)
		} else {
			fhctx.NotFound()
		}
	case endpoint.ENDPOINTSTRING_CONFIG:
		if config.Config.Server.EnableDebugEndpoints {
			configInfo(fhctx)
		} else {
			fhctx.NotFound()
		}
	default:
		if config.Config.Server.EnableDebugEndpoints && profilingHandler(fhctx) {
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

	logger.LogRequest(fhctx)
	monitoringRequestLatency.Observe(float64(time.Since(fhctx.Time())) / float64(time.Second))
}

func Run(sub *submitter.Submitter, mon *monitor.Monitor) {
	webServer = &fasthttp.Server{
		Handler:               func(fhctx *fasthttp.RequestCtx) { webHandler(fhctx, sub, mon) },
		CloseOnShutdown:       true,
		ReadTimeout:           config.Config.Server.ReadTimeout,
		IdleTimeout:           config.Config.Server.IdleTimeout,
		DisableKeepalive:      config.Config.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if config.Config.Server.WebserverPort != 0 {
		logger.Logger.Info("Starting WebServer", zap.Int("port", config.Config.Server.WebserverPort))
		go func() {
			if err := webServer.ListenAndServe(fmt.Sprintf(":%d", config.Config.Server.WebserverPort)); err != nil {
				logger.Logger.Fatal("webServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if config.Config.Server.WebserverPath != "" {
		logger.Logger.Info("Starting WebServer", zap.String("path", config.Config.Server.WebserverPath))
		go func() {
			if err := webServer.ListenAndServeUNIX(config.Config.Server.WebserverPath, config.Config.Server.SocketPermissions); err != nil {
				logger.Logger.Fatal("webServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}

	monitoringServer = &fasthttp.Server{
		Handler:               func(fhctx *fasthttp.RequestCtx) { monitoringHandler(fhctx, mon) },
		CloseOnShutdown:       true,
		ReadTimeout:           config.Config.Server.ReadTimeout,
		IdleTimeout:           config.Config.Server.IdleTimeout,
		DisableKeepalive:      config.Config.Server.DisableKeepalive,
		NoDefaultServerHeader: true,
	}
	if config.Config.Server.MonitoringPort != 0 {
		listenAddr := fmt.Sprintf("%s:%d", config.Config.Server.MonitoringAddress, config.Config.Server.MonitoringPort)
		if config.Config.Server.MonitoringAddress == "" || config.Config.Server.MonitoringAddress == "0.0.0.0" {
			logger.Logger.Warn("MonitoringServer is binding to all interfaces; set server.monitoringAddress (e.g. \"127.0.0.1\") to restrict access in hardened/sidecar deployments", zap.Int("port", config.Config.Server.MonitoringPort))
		}
		logger.Logger.Info("Starting MonitoringServer", zap.String("address", listenAddr))
		go func() {
			if err := monitoringServer.ListenAndServe(listenAddr); err != nil {
				logger.Logger.Fatal("monitoringServer.ListenAndServe failed", zap.Error(err))
			}
		}()
	}
	if config.Config.Server.MonitoringPath != "" {
		logger.Logger.Info("Starting MonitoringServer", zap.String("path", config.Config.Server.MonitoringPath))
		go func() {
			if err := monitoringServer.ListenAndServeUNIX(config.Config.Server.MonitoringPath, config.Config.Server.SocketPermissions); err != nil {
				logger.Logger.Fatal("monitoringServer.ListenAndServeUNIX failed", zap.Error(err))
			}
		}()
	}
}

func Shutdown() {
	logger.Logger.Info("Stopping WebServer (gracefully)")
	if err := webServer.Shutdown(); err != nil {
		logger.Logger.Error("webServer.Shutdown failed", zap.Error(err))
	}
	logger.Logger.Info("Stopped WebServer")

	logger.Logger.Info("Stopping MonitoringServer (gracefully)")
	if err := monitoringServer.Shutdown(); err != nil {
		logger.Logger.Error("monitoringServer.Shutdown failed", zap.Error(err))
	}
	logger.Logger.Info("Stopped MonitoringServer")
}
