package server

import (
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/monitor"

	"github.com/valyala/fasthttp"
)

func newMonitoringGetCtx(path string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI(path)
	return ctx
}

func TestDebugEndpointsReturn404WhenDisabled(t *testing.T) {
	config.Config.Server.EnableDebugEndpoints = false
	mon := monitor.New(&config.Config)

	for _, path := range []string{"/debug/build", "/debug/config", "/debug/pprof/", "/debug/pprof/heap"} {
		ctx := newMonitoringGetCtx(path)
		monitoringHandler(ctx, mon)
		if got := ctx.Response.StatusCode(); got != fasthttp.StatusNotFound {
			t.Errorf("path %s: expected 404 when debug endpoints disabled, got %d", path, got)
		}
	}
}

func TestDebugEndpointsServedWhenEnabled(t *testing.T) {
	config.Config.Server.EnableDebugEndpoints = true
	defer func() { config.Config.Server.EnableDebugEndpoints = false }()
	mon := monitor.New(&config.Config)

	for _, path := range []string{"/debug/build", "/debug/config"} {
		ctx := newMonitoringGetCtx(path)
		monitoringHandler(ctx, mon)
		if got := ctx.Response.StatusCode(); got != fasthttp.StatusOK {
			t.Errorf("path %s: expected 200 when debug endpoints enabled, got %d", path, got)
		}
		if len(ctx.Response.Body()) == 0 {
			t.Errorf("path %s: expected non-empty response body", path)
		}
	}
}
