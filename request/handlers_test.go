package request

import (
	"errors"
	"strings"
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/submitter"

	json "github.com/goccy/go-json"
	"github.com/valyala/fasthttp"
)

func TestCSS(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	CSS(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("CSS status: got %d, want 200", ctx.Response.StatusCode())
	}
	if len(ctx.Response.Body()) == 0 {
		t.Error("CSS body is empty")
	}
}

func TestFrontPage(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	FrontPage(ctx)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("FrontPage status: got %d, want 200", ctx.Response.StatusCode())
	}
	if len(ctx.Response.Body()) == 0 {
		t.Error("FrontPage body is empty")
	}
}

func TestAPIWebpage(t *testing.T) {
	for _, path := range []string{"add-chain", "add-pre-chain"} {
		ctx := &fasthttp.RequestCtx{}
		APIWebpage(ctx, path)
		if ctx.Response.StatusCode() != fasthttp.StatusOK {
			t.Errorf("APIWebpage(%s) status: got %d, want 200", path, ctx.Response.StatusCode())
		}
		if len(ctx.Response.Body()) == 0 {
			t.Errorf("APIWebpage(%s) body is empty", path)
		}
	}
}

func TestLogList(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	LogList(ctx, loglists.UsableTLSLogs, "Usable TLS Logs")
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("LogList status: got %d, want 200", ctx.Response.StatusCode())
	}
	if len(ctx.Response.Body()) == 0 {
		t.Error("LogList body is empty")
	}
}

func TestDashboardRender(t *testing.T) {
	cfg := config.MustLoad()
	mon := monitor.New(cfg)
	ctx := &fasthttp.RequestCtx{}
	Dashboard(ctx, cfg, mon)
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Errorf("Dashboard status: got %d, want 200", ctx.Response.StatusCode())
	}
	if len(ctx.Response.Body()) == 0 {
		t.Error("Dashboard body is empty")
	}
}

func TestSendJSONResponse(t *testing.T) {
	cfg := config.MustLoad()
	for _, pretty := range []bool{false, true} {
		cfg.Response.JsonPrettyPrint = pretty
		ctx := &fasthttp.RequestCtx{}
		if got := sendJSONResponse(ctx, cfg, &submitter.SubmissionResponse{}); got != fasthttp.StatusOK {
			t.Errorf("sendJSONResponse(pretty=%v): got %d, want 200", pretty, got)
		}
	}
}

func TestSendHTMLResponseSuccess(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if got := sendHTMLResponse(ctx, &submitter.SubmissionResponse{}, nil); got != fasthttp.StatusOK {
		t.Errorf("sendHTMLResponse(success): got %d, want 200", got)
	}
}

func TestSendHTMLResponseErrorIncludesStrategy(t *testing.T) {
	resp := &submitter.SubmissionResponse{Strategy: []submitter.StrategyMember{{
		Operator:      "Test Operator",
		LogName:       "Test Log",
		SubmissionURL: "https://log.example.com/",
		Outcome:       "Failed: connection refused",
	}}}

	ctx := &fasthttp.RequestCtx{}
	if got := sendHTMLResponse(ctx, resp, errors.New("quorum not achieved")); got != fasthttp.StatusBadRequest {
		t.Errorf("sendHTMLResponse(error): got %d, want 400", got)
	}

	body := string(ctx.Response.Body())
	for _, want := range []string{"quorum not achieved", "Strategy", "Test Log", "Failed: connection refused"} {
		if !strings.Contains(body, want) {
			t.Errorf("response body does not contain %q:\n%s", want, body)
		}
	}
}

func TestSendHTMLResponseErrorWithoutStrategy(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if got := sendHTMLResponse(ctx, nil, errors.New("empty request body")); got != fasthttp.StatusBadRequest {
		t.Errorf("sendHTMLResponse(error): got %d, want 400", got)
	}

	if body := string(ctx.Response.Body()); strings.Contains(body, "Strategy") {
		t.Errorf("response body unexpectedly contains a strategy table:\n%s", body)
	}
}

func TestSendJSONProblemIncludesStrategy(t *testing.T) {
	resp := &submitter.SubmissionResponse{Strategy: []submitter.StrategyMember{{
		Operator:      "Test Operator",
		LogName:       "Test Log",
		SubmissionURL: "https://log.example.com/",
		Outcome:       "Failed: connection refused",
	}}}

	ctx := &fasthttp.RequestCtx{}
	if got := sendJSONProblem(ctx, fasthttp.StatusBadRequest, resp, errors.New("quorum not achieved")); got != fasthttp.StatusBadRequest {
		t.Errorf("sendJSONProblem: got %d, want 400", got)
	}

	var body struct {
		Detail   string `json:"detail"`
		Strategy []struct {
			LogName string `json:"logName"`
			Outcome string `json:"outcome"`
		} `json:"strategy"`
	}
	if err := json.Unmarshal(ctx.Response.Body(), &body); err != nil {
		t.Fatalf("failed to unmarshal problem response: %v", err)
	}
	if body.Detail != "quorum not achieved" {
		t.Errorf("detail: got %q", body.Detail)
	}
	if len(body.Strategy) != 1 || body.Strategy[0].LogName != "Test Log" || body.Strategy[0].Outcome != "Failed: connection refused" {
		t.Errorf("strategy: got %+v", body.Strategy)
	}
}

func TestSendJSONProblemWithoutStrategy(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if got := sendJSONProblem(ctx, fasthttp.StatusBadRequest, nil, errors.New("empty request body")); got != fasthttp.StatusBadRequest {
		t.Errorf("sendJSONProblem: got %d, want 400", got)
	}

	if body := string(ctx.Response.Body()); strings.Contains(body, "strategy") {
		t.Errorf("problem response unexpectedly contains a strategy:\n%s", body)
	}
}
