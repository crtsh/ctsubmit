package server

import (
	"net"
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/submitter"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func newInmemClient(t *testing.T, handler fasthttp.RequestHandler) *fasthttp.HostClient {
	t.Helper()
	ln := fasthttputil.NewInmemoryListener()
	srv := &fasthttp.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return &fasthttp.HostClient{Dial: func(string) (net.Conn, error) { return ln.Dial() }}
}

func doRequest(t *testing.T, c *fasthttp.HostClient, method, path, body string) {
	t.Helper()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("http://localhost" + path)
	req.Header.SetMethod(method)
	if body != "" {
		req.SetBodyString(body)
	}
	if err := c.Do(req, resp); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
}

func TestServerEndpoints(t *testing.T) {
	cfg := config.MustLoad()
	// Ports/paths off: Run creates the server structs (needed by getFastHTTPMetrics)
	// and Shutdown tears them down, without binding any sockets.
	cfg.Server.WebserverPort = 0
	cfg.Server.MonitoringPort = 0
	cfg.Server.WebserverPath = ""
	cfg.Server.MonitoringPath = ""
	cfg.Server.EnableDebugEndpoints = true

	mon := monitor.New(cfg)
	sub := submitter.New(cfg, logger.Logger, mon)

	Run(cfg, sub, mon)
	defer Shutdown()

	health.SetInitialDataReady() // so /readyz reports ready

	monClient := newInmemClient(t, func(ctx *fasthttp.RequestCtx) { monitoringHandler(ctx, cfg, mon) })
	for _, p := range []string{
		"/livez", "/readyz", "/metrics",
		"/ctsubmit.css", "/dashboard", "/favicon.ico", "/mascot.png",
		"/debug/build", "/debug/config", "/debug/pprof/heap",
		"/nonexistent",
	} {
		doRequest(t, monClient, fasthttp.MethodGet, p, "")
	}

	webClient := newInmemClient(t, func(ctx *fasthttp.RequestCtx) { webHandler(ctx, cfg, sub, mon) })
	for _, p := range []string{
		"/", "/ctsubmit.css", "/dashboard", "/favicon.ico", "/mascot.png",
		"/usable_tls_logs.json", "/active_tls_logs.json", "/test_tls_logs.json", "/usable_bimi_logs.json",
		"/add-chain", "/add-pre-chain", "/nonexistent",
	} {
		doRequest(t, webClient, fasthttp.MethodGet, p, "")
	}
	// A POST exercises the submission path (empty chain -> error response).
	doRequest(t, webClient, fasthttp.MethodPost, "/add-chain", `{"chain":[]}`)
	// An unsupported method exercises the method-not-allowed branch.
	doRequest(t, webClient, fasthttp.MethodPut, "/", "")
}
