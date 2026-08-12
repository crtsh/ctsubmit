package request

import (
	"net"
	"strings"
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/submitter"

	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttputil"
)

func testSubmitter() *submitter.Submitter {
	cfg := config.MustLoad()
	return submitter.New(cfg, logger.Logger, monitor.New(cfg))
}

func TestGetResponseFormatFromParam(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.SetRequestURI("/add-chain?format=html")
	if got := getResponseFormat(ctx); got != config.RESPONSEFORMAT_HTML {
		t.Fatalf("expected HTML from format param, got %v", got)
	}
}

func TestGetResponseFormatFromAcceptHeader(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Accept", "text/html")
	if got := getResponseFormat(ctx); got != config.RESPONSEFORMAT_HTML {
		t.Fatalf("expected HTML from Accept header, got %v", got)
	}

	ctx = &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Accept", "application/json")
	if got := getResponseFormat(ctx); got != config.RESPONSEFORMAT_JSON {
		t.Fatalf("expected JSON from Accept header, got %v", got)
	}
}

func TestGetResponseFormatDefault(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	if got := getResponseFormat(ctx); got != config.DefaultResponseFormat {
		t.Fatalf("expected default response format, got %v", got)
	}
}

func TestPOSTUnknownEndpointReturns404(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/not-a-real-endpoint")
	ctx.Request.SetBody([]byte(`{"chain":[]}`))

	if got := POST(ctx, "not-a-real-endpoint", config.MustLoad(), testSubmitter()); got != fasthttp.StatusNotFound {
		t.Fatalf("expected 404 for unknown endpoint, got %d", got)
	}
}

func TestPOSTEmptyBodyReturnsBadRequest(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/add-chain")

	if got := POST(ctx, "add-chain", config.MustLoad(), testSubmitter()); got != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", got)
	}
}

func TestPOSTTimeoutReturnsMinusOne(t *testing.T) {
	// A bare RequestCtx has a zero Time(), so the request deadline computed from
	// it is already in the past and POST must take the timeout path.
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/add-chain")
	ctx.Request.SetBody([]byte(`{"chain":["AQID"]}`))

	if got := POST(ctx, "add-chain", config.MustLoad(), testSubmitter()); got != -1 {
		t.Fatalf("expected -1 (timeout) for an already-expired request context, got %d", got)
	}
}

// newInmemHandlerClient runs POST behind an in-memory fasthttp server so that
// RequestCtx.Time() is populated (a manually-built ctx has a zero time, which
// forces the timeout path). It returns a client wired to that server.
func newInmemHandlerClient(t *testing.T) *fasthttp.HostClient {
	t.Helper()
	ln := fasthttputil.NewInmemoryListener()
	sub := testSubmitter()
	cfg := config.MustLoad()
	srv := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			path := strings.ToLower(string(ctx.Path()))
			if len(path) > 0 {
				path = path[1:]
			}
			if POST(ctx, path, cfg, sub) == -1 {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return &fasthttp.HostClient{
		Dial: func(string) (net.Conn, error) { return ln.Dial() },
	}
}

func doPOST(t *testing.T, client *fasthttp.HostClient, path, accept, body string) (int, string, string) {
	t.Helper()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://inmem/" + path)
	req.Header.SetMethod(fasthttp.MethodPost)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.SetBodyString(body)

	if err := client.Do(req, resp); err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	return resp.StatusCode(), string(resp.Header.ContentType()), string(resp.Body())
}

func TestPOSTJSONProblemOnParseError(t *testing.T) {
	client := newInmemHandlerClient(t)

	// "AQID" is base64 for 0x01 0x02 0x03, which is not a valid certificate, so
	// the handler fails and returns a JSON Problem response.
	status, contentType, body := doPOST(t, client, "add-chain", "application/json", `{"chain":["AQID"]}`)

	if status != fasthttp.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", status)
	}
	if !strings.Contains(contentType, "problem+json") {
		t.Fatalf("content type: got %q, want application/problem+json", contentType)
	}
	if !strings.Contains(body, "parse") {
		t.Fatalf("expected the problem detail to mention the parse failure, got %q", body)
	}
}

func TestPOSTJSONProblemOnInvalidJSON(t *testing.T) {
	client := newInmemHandlerClient(t)

	status, contentType, _ := doPOST(t, client, "add-chain", "application/json", `{not valid json`)

	if status != fasthttp.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", status)
	}
	if !strings.Contains(contentType, "problem+json") {
		t.Fatalf("content type: got %q, want application/problem+json", contentType)
	}
}

func TestPOSTHTMLErrorResponse(t *testing.T) {
	client := newInmemHandlerClient(t)

	status, contentType, body := doPOST(t, client, "add-chain", "text/html", `{"chain":["AQID"]}`)

	if status != fasthttp.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", status)
	}
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("content type: got %q, want text/html", contentType)
	}
	if len(body) == 0 {
		t.Fatal("expected a non-empty HTML error body")
	}
}
