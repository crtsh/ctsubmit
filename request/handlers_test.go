package request

import (
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/submitter"

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
