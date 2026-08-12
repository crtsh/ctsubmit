package server

import (
	"context"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/health"
	"github.com/crtsh/ctsubmit/utils"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func livez(ctx *fasthttp.RequestCtx, cfg *config.Settings, h *health.Health) int {
	ctx.SetUserValue("level", zap.DebugLevel)
	ctx.SetUserValue("msg", "Liveness check")

	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), ctx.Time().Add(time.Duration(cfg.Server.LivezTimeout)))
	defer cancel()

	doneChan := make(chan int, 1)
	go func() {
		statusCode := fasthttp.StatusOK
		if !h.IsAlive(ctx) {
			statusCode = fasthttp.StatusServiceUnavailable
		}

		// Return a response.
		ctx.SetContentType("text/plain")
		ctx.SetStatusCode(statusCode)
		if !ctx.IsHead() {
			if statusCode == fasthttp.StatusOK {
				ctx.SetBody(utils.S2B("OK"))
			} else {
				ctx.SetBody(utils.S2B("ERROR"))
			}
		}
		doneChan <- 0
	}()

	select {
	case status := <-doneChan:
		return status
	case <-ctxWithDeadline.Done():
		return -1 // Request timed out.
	}
}
