package request

import (
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/request/templates"

	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func Dashboard(fhctx *fasthttp.RequestCtx) {
	var logList *loglist3.LogList
	logListName := ""
	switch paramS(fhctx, "loglist") {
	case "usabletls", "": // default
		logList = loglists.UsableTLSLogs
		logListName = "Usable TLS Log"
	case "activetls":
		logList = loglists.ActiveTLSLogs
		logListName = "Active TLS Log"
	case "testtls":
		logList = loglists.TestTLSLogs
		logListName = "Test TLS Log"
	case "usablebimi":
		logList = loglists.UsableBIMILogs
		logListName = "Usable BIMI Log"
	default:
		fhctx.NotFound()
		logger.SetDetails(fhctx, zap.InfoLevel, "Invalid loglist query parameter", nil, nil)
		return
	}

	var logs []templates.DashboardLog
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			logs = append(logs, templates.DashboardLog{
				OperatorName:   operator.Name,
				LogDescription: log.Description,
				MonitoringURL:  log.URL,
				SubmissionURL:  log.URL,
				LogType:        "RFC6962",
				MMD:            log.MMD,
			})
		}

		for _, tiledLog := range operator.TiledLogs {
			logs = append(logs, templates.DashboardLog{
				OperatorName:   operator.Name,
				LogDescription: tiledLog.Description,
				MonitoringURL:  tiledLog.MonitoringURL,
				SubmissionURL:  tiledLog.SubmissionURL,
				LogType:        "Static CT",
				MMD:            tiledLog.MMD,
			})
		}
	}

	logger.SetDetails(fhctx, zap.InfoLevel, "Dashboard", nil, nil)
	fhctx.SetContentType("text/html")
	fhctx.SetStatusCode(fasthttp.StatusOK)
	templates.WriteDashboardPage(fhctx, logListName, logs)
}
