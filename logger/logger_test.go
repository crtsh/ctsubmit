package logger

import (
	"errors"
	"net"
	"testing"

	"github.com/crtsh/ctsubmit/config"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestInitLogger(t *testing.T) {
	l, err := InitLogger(config.MustLoad())
	if err != nil {
		t.Fatalf("InitLogger(default): %v", err)
	}
	if l == nil {
		t.Fatal("InitLogger returned a nil logger")
	}

	dev := config.MustLoad()
	dev.Logging.IsDevelopment = true
	dev.Logging.Level = "debug"
	dev.Logging.SamplingInitial = 10
	dev.Logging.SamplingThereafter = 10
	if _, err := InitLogger(dev); err != nil {
		t.Fatalf("InitLogger(development+sampling+level): %v", err)
	}

	bad := config.MustLoad()
	bad.Logging.Level = "not-a-level"
	if _, err := InitLogger(bad); err == nil {
		t.Fatal("InitLogger with an invalid level should return an error")
	}
}

func TestSetDetails(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	SetDetails(ctx, zap.WarnLevel, "hello", errors.New("boom"), []zap.Field{zap.String("k", "v")})
	if ctx.UserValue("level") != zapcore.WarnLevel {
		t.Errorf("level not set correctly")
	}
	if ctx.UserValue("msg") != "hello" {
		t.Errorf("msg not set correctly")
	}
	if ctx.UserValue("error") == nil {
		t.Errorf("error should be set")
	}
	if ctx.UserValue("zap_fields") == nil {
		t.Errorf("zap_fields should be set")
	}

	// A nil error and nil fields leave those user values unset.
	bare := &fasthttp.RequestCtx{}
	SetDetails(bare, zap.InfoLevel, "x", nil, nil)
	if bare.UserValue("error") != nil {
		t.Errorf("error should be unset when nil")
	}
	if bare.UserValue("zap_fields") != nil {
		t.Errorf("zap_fields should be unset when nil")
	}
}

func TestGetRealClientIP(t *testing.T) {
	newCtx := func() *fasthttp.RequestCtx {
		ctx := &fasthttp.RequestCtx{}
		ctx.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 4321})
		return ctx
	}

	// X-Real-IP takes precedence over everything else.
	ctx := newCtx()
	ctx.Request.Header.Set("X-Real-IP", "198.51.100.7")
	ctx.Request.Header.Set("X-Forwarded-For", "1.1.1.1")
	if got := getRealClientIP(ctx); got != "198.51.100.7" {
		t.Errorf("X-Real-IP: got %q, want 198.51.100.7", got)
	}

	// X-Forwarded-For uses the last entry by default.
	ctx = newCtx()
	ctx.Request.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")
	XFFUseFirstIPAddress = false
	if got := getRealClientIP(ctx); got != "3.3.3.3" {
		t.Errorf("XFF (last): got %q, want 3.3.3.3", got)
	}

	// ...and the first entry when configured to.
	XFFUseFirstIPAddress = true
	if got := getRealClientIP(ctx); got != "1.1.1.1" {
		t.Errorf("XFF (first): got %q, want 1.1.1.1", got)
	}
	XFFUseFirstIPAddress = false

	// With no forwarding headers, fall back to the remote address.
	ctx = newCtx()
	if got := getRealClientIP(ctx); got != "203.0.113.9" {
		t.Errorf("remote address fallback: got %q, want 203.0.113.9", got)
	}
}

func TestLogRequest(t *testing.T) {
	lgr := zap.NewNop()

	for _, level := range []zapcore.Level{zap.ErrorLevel, zap.WarnLevel, zap.InfoLevel, zap.DebugLevel} {
		ctx := &fasthttp.RequestCtx{}
		ctx.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1})
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)
		ctx.Request.Header.SetContentType("application/json")
		ctx.Request.Header.Set("User-Agent", "test-agent")
		SetDetails(ctx, level, "msg", errors.New("e"), []zap.Field{zap.String("k", "v")})
		LogRequest(lgr, ctx) // must not panic and must hit the level's switch arm.
	}

	// No user values set: defaults to Error level with an empty message.
	LogRequest(lgr, &fasthttp.RequestCtx{})
}
