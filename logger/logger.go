package logger

import (
	"math"
	"net"
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
	// Logger defaults to a no-op so it is safe to use before InitLogger runs
	// (e.g. in tests). main replaces it via InitLogger at startup.
	Logger               = zap.NewNop()
	ShutdownWG           sync.WaitGroup
	XFFUseFirstIPAddress bool
)

func InitLogger(cfg *config.Settings) error {
	XFFUseFirstIPAddress = cfg.Logging.XFFUseFirstIPAddress

	// Create and configure a Zap logger.
	var err error
	var zapCfg zap.Config
	if cfg.Logging.IsDevelopment {
		zapCfg = zap.NewDevelopmentConfig() // "debug" and above; console-friendly output.
	} else {
		zapCfg = zap.NewProductionConfig() // "info" and above; JSON output.
		zapCfg.DisableCaller = true
	}
	// Override log level threshold, if required.
	if cfg.Logging.Level != "" {
		if zapCfg.Level, err = zap.ParseAtomicLevel(cfg.Logging.Level); err != nil {
			return err
		}
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

	Logger, err = zapCfg.Build()
	return err
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

func LogRequest(l *zap.Logger, fhctx *fasthttp.RequestCtx) {
	// Add common logging details.
	zf := []zap.Field{
		zap.String("client_ip", getRealClientIP(fhctx)),
		zap.ByteString("http_method", fhctx.Method()),
		zap.Int("http_status", fhctx.Response.StatusCode()),
		zap.ByteString("protocol", fhctx.Request.Header.Protocol()),
		zap.ByteString("raw_path", fhctx.RequestURI()),
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
		l.Error(msg, zf...)
	case zap.WarnLevel:
		l.Warn(msg, zf...)
	case zap.InfoLevel:
		l.Info(msg, zf...)
	case zap.DebugLevel:
		l.Debug(msg, zf...)
	}
}
