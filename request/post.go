package request

import (
	"context"
	"fmt"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/request/templates"
	"github.com/crtsh/ctsubmit/submitter"
	"github.com/crtsh/ctsubmit/utils"

	json "github.com/goccy/go-json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/valyala/fasthttp"

	"go.uber.org/zap"

	"schneider.vip/problem"
)

var endpointRequestCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "endpoint",
	Name:      "requests_total",
	Help:      "Total requests per submission endpoint, by result.",
}, []string{"endpoint", "result"})

func getResponseFormat(fhctx *fasthttp.RequestCtx) config.ResponseFormat {
	if f := paramS(fhctx, "format"); f != "" {
		return config.ParseResponseFormat(f)
	} else {
		switch utils.B2S(fhctx.Request.Header.Peek("Accept")) {
		case "text/html":
			return config.RESPONSEFORMAT_HTML
		case "application/json":
			return config.RESPONSEFORMAT_JSON
		}
	}

	return config.DefaultResponseFormat
}

func POST(fhctx *fasthttp.RequestCtx, path string, cfg *config.Settings, sub *submitter.Submitter, h *health.Health) int {
	status := fasthttp.StatusBadRequest

	ctx, cancel := context.WithDeadline(context.Background(), fhctx.Time().Add(time.Duration(cfg.Server.RequestTimeout)))
	defer cancel()

	// Read all inputs from fhctx before any potentially long-running work.
	apiEndpoint, ok := endpoint.CheckPOSTEndpoint(path)
	if !ok {
		logger.SetDetails(fhctx, zap.InfoLevel, "Invalid endpoint", nil, nil)
		fhctx.SetStatusCode(fasthttp.StatusNotFound)
		return fasthttp.StatusNotFound
	}

	var err error
	defer func() {
		result := "success"
		if err != nil {
			result = "error"
		}
		endpointRequestCounter.WithLabelValues(endpoint.APIEndpoint[apiEndpoint], result).Inc()
		logger.SetDetails(fhctx, zap.InfoLevel, "Submission Request", err, nil)
		if ctx.Err() == nil {
			fhctx.SetStatusCode(status)
		}
	}()

	responseFormat := getResponseFormat(fhctx)
	if responseFormat == -1 {
		err = fmt.Errorf("unrecognised response format")
		return status
	}

	requestBody := fhctx.Request.Body()
	if len(requestBody) == 0 {
		err = fmt.Errorf("empty request body")
		return status
	}

	submissionRequest := submitter.NewSubmissionRequest()
	var submissionResponse *submitter.SubmissionResponse
	if err = json.Unmarshal(requestBody, submissionRequest); err == nil {
		submissionResponse, err = sub.Handle(ctx, apiEndpoint, submissionRequest)
		if err == nil {
			status = fasthttp.StatusOK
		}
	}

	// If the request deadline was exceeded, update health tracking and return early.
	if ctx.Err() != nil {
		deadline, _ := ctx.Deadline()
		h.UpdateLatestTimestamps(nil, nil, &deadline)
		return -1
	}

	// Add permissive Cross-Origin Resource Sharing (CORS) response header.  This is intentional: as a public CT submission proxy, we allow
	// browser-based tools and web applications to submit certificates directly without requiring a server-side relay.
	fhctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	// Send response.
	switch responseFormat {
	case config.RESPONSEFORMAT_HTML:
		status = sendHTMLResponse(fhctx, submissionResponse, err)
	case config.RESPONSEFORMAT_JSON:
		if err == nil {
			status = sendJSONResponse(fhctx, cfg, submissionResponse)
		} else {
			status = sendJSONProblem(fhctx, status, submissionResponse, err)
		}
	}
	return status
}

func paramS(fhctx *fasthttp.RequestCtx, name string) string {
	return utils.B2S(paramB(fhctx, name))
}

func paramB(fhctx *fasthttp.RequestCtx, name string) []byte {
	if arg := fhctx.PostArgs().Peek(name); len(arg) > 0 {
		return arg
	} else if arg = fhctx.QueryArgs().Peek(name); len(arg) > 0 {
		return arg
	} else if form, err := fhctx.MultipartForm(); err == nil {
		if s := form.Value[name]; len(s) > 0 {
			return utils.S2B(s[0])
		}
	}

	return nil
}

func sendHTMLResponse(fhctx *fasthttp.RequestCtx, submissionResponse *submitter.SubmissionResponse, err error) int {
	fhctx.SetContentType("text/html; charset=UTF-8")

	if err != nil {
		templates.WriteHTMLError(fhctx, err.Error())
		if hasStrategy(submissionResponse) {
			templates.WriteHTMLResponse(fhctx, submissionResponse)
		}
		return fasthttp.StatusBadRequest
	}

	templates.WriteHTMLResponse(fhctx, submissionResponse)
	return fasthttp.StatusOK
}

func hasStrategy(submissionResponse *submitter.SubmissionResponse) bool {
	return submissionResponse != nil && len(submissionResponse.Strategy) > 0
}

func sendJSONResponse(fhctx *fasthttp.RequestCtx, cfg *config.Settings, submissionResponse *submitter.SubmissionResponse) int {
	// Encode and send the results as JSON.
	fhctx.SetContentType("application/json; charset=UTF-8")

	j := json.NewEncoder(fhctx)
	j.SetEscapeHTML(false)
	if cfg.Response.JsonPrettyPrint {
		j.SetIndent("", "  ")
	}
	if err := j.Encode(submissionResponse); err != nil {
		logger.SetDetails(fhctx, zap.ErrorLevel, "Failed to encode JSON", nil, nil)
	}

	return fasthttp.StatusOK
}

func sendJSONProblem(fhctx *fasthttp.RequestCtx, status int, submissionResponse *submitter.SubmissionResponse, err error) int {
	// Encode and send the error as a JSON Problem response.
	fhctx.SetContentType(problem.ContentTypeJSON)
	p := problem.Of(status).Append(problem.Detail(err.Error()))
	if hasStrategy(submissionResponse) {
		p = p.Append(problem.Custom("strategy", submissionResponse.Strategy))
	}
	fhctx.SetBody(p.JSON())

	return status
}
