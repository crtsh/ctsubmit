package request

import (
	"testing"

	"github.com/crtsh/ctsubmit/config"

	"github.com/valyala/fasthttp"
)

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

	if got := POST(ctx, "not-a-real-endpoint"); got != fasthttp.StatusNotFound {
		t.Fatalf("expected 404 for unknown endpoint, got %d", got)
	}
}

func TestPOSTEmptyBodyReturnsBadRequest(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/add-chain")

	if got := POST(ctx, "add-chain"); got != fasthttp.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d", got)
	}
}
