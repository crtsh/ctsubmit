package logger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/utils"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	ShutdownWG           sync.WaitGroup
	XFFUseFirstIPAddress bool
)

// instancePrefix distinguishes request IDs minted by different ctsubmit processes, because
// fasthttp's request counter restarts from zero every time the process does.
var instancePrefix = newInstancePrefix()

func newInstancePrefix() string {
	var b [4]byte
	_, _ = rand.Read(b[:]) // Cannot fail; crypto/rand panics rather than returning an error.
	return hex.EncodeToString(b[:])
}

// RequestID returns an identifier for this request that is unique across ctsubmit processes:
// the per-process prefix, plus fasthttp's (connection ID << 32 | request number) counter pair.
func RequestID(fhctx *fasthttp.RequestCtx) string {
	return instancePrefix + "-" + strconv.FormatUint(fhctx.ID(), 16)
}

// InitLogger builds the application's zap.Logger from cfg and returns it for
// injection into the components that need it; the logger package no longer
// holds it as a package-level global.
func InitLogger(cfg *config.Settings) (*zap.Logger, error) {
	XFFUseFirstIPAddress = cfg.Logging.XFFUseFirstIPAddress

	// Create and configure a Zap logger.
	var zapCfg zap.Config
	if cfg.Logging.IsDevelopment {
		zapCfg = zap.NewDevelopmentConfig() // "debug" and above; console-friendly output.
	} else {
		zapCfg = zap.NewProductionConfig() // "info" and above; JSON output.
		zapCfg.DisableCaller = true
	}
	// Override log level threshold, if required.
	if cfg.Logging.Level != "" {
		level, err := zap.ParseAtomicLevel(cfg.Logging.Level)
		if err != nil {
			return nil, err
		}
		zapCfg.Level = level
	}
	// Configure or disable log sampling.
	if cfg.Logging.SamplingInitial == math.MaxInt && cfg.Logging.SamplingThereafter == math.MaxInt {
		zapCfg.Sampling = nil // Disable sampling.
	} else {
		zapCfg.Sampling = &zap.SamplingConfig{
			Initial:    cfg.Logging.SamplingInitial,
			Thereafter: cfg.Logging.SamplingThereafter,
		}
	}
	// Configure timestamp format.
	zapCfg.EncoderConfig.TimeKey = "@timestamp"
	zapCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	zapCfg.EncoderConfig.EncodeDuration = zapcore.NanosDurationEncoder

	return zapCfg.Build()
}

func SetDetails(fhctx *fasthttp.RequestCtx, level zapcore.Level, msg string, err error, extraFields []zap.Field) {
	fhctx.SetUserValue("level", level)
	fhctx.SetUserValue("msg", msg)
	if err != nil {
		fhctx.SetUserValue("error", err)
	}
	if extraFields != nil {
		fhctx.SetUserValue("zap_fields", extraFields)
	}
}

type loggerContextKey struct{}

// NewContext returns a copy of ctx carrying lgr, so that components handling a request can log
// with the request-scoped fields (request_id, etc) that the caller attached to it.
func NewContext(ctx context.Context, lgr *zap.Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey{}, lgr)
}

// FromContext returns the logger stored in ctx by NewContext, or fallback if there isn't one.
func FromContext(ctx context.Context, fallback *zap.Logger) *zap.Logger {
	if lgr, ok := ctx.Value(loggerContextKey{}).(*zap.Logger); ok && lgr != nil {
		return lgr
	}
	return fallback
}

func getRealClientIP(fhctx *fasthttp.RequestCtx) string {
	remoteAddr := fhctx.RemoteAddr().String()
	// Split host and port - handling both IPv4 and IPv6.
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteAddr = host
	}
	if realIP := fhctx.Request.Header.Peek("X-Real-IP"); len(realIP) > 0 {
		return utils.B2S(realIP)
	}
	if xff := fhctx.Request.Header.Peek("X-Forwarded-For"); len(xff) > 0 {
		ipAddress := strings.Split(utils.B2S(xff), ",")
		if XFFUseFirstIPAddress {
			return strings.TrimSpace(ipAddress[0]) // The original client's claimed IP.
		}
		return strings.TrimSpace(ipAddress[len(ipAddress)-1]) // The entry most likely added by a trusted proxy.
	}
	return remoteAddr
}

func LogRequest(lgr *zap.Logger, fhctx *fasthttp.RequestCtx) {
	// Add common logging details.
	zf := []zap.Field{
		zap.String("client_ip", getRealClientIP(fhctx)),
		zap.ByteString("http_method", fhctx.Method()),
		zap.Int("http_status", fhctx.Response.StatusCode()),
		zap.ByteString("protocol", fhctx.Request.Header.Protocol()),
		zap.ByteString("raw_path", fhctx.RequestURI()),
		zap.String("request_id", RequestID(fhctx)),
		zap.Int("response_body_size", len(fhctx.Response.Body())),
		zap.Duration("time_taken_ns", time.Since(fhctx.Time())),
	}

	// Add further optional logging details.
	if e := fhctx.UserValue("error"); e != nil {
		zf = append(zf, zap.Error(e.(error)))
	}
	if ct := fhctx.Request.Header.ContentType(); len(ct) > 0 {
		zf = append(zf, zap.ByteString("request_content_type", ct))
	}
	if ua := fhctx.Request.Header.UserAgent(); len(ua) > 0 {
		zf = append(zf, zap.ByteString("user_agent", ua))
	}

	// Add application-specific details.
	if f := fhctx.UserValue("zap_fields"); f != nil {
		zf = append(zf, f.([]zapcore.Field)...)
	}

	// Get the error level and message.
	level := zap.ErrorLevel
	if l := fhctx.UserValue("level"); l != nil {
		level = l.(zapcore.Level)
	}

	msg := ""
	if m := fhctx.UserValue("msg"); m != nil {
		msg = m.(string)
	}

	// Write the log entry.
	switch level {
	case zap.ErrorLevel:
		lgr.Error(msg, zf...)
	case zap.WarnLevel:
		lgr.Warn(msg, zf...)
	case zap.InfoLevel:
		lgr.Info(msg, zf...)
	case zap.DebugLevel:
		lgr.Debug(msg, zf...)
	}
}
