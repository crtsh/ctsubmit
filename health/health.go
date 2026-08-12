package health

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/crtsh/ctsubmit/config"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

// Health tracks the liveness/readiness signals for the service: the latest
// success/error/busy timestamps and whether initial external data has loaded.
// Construct one with New.
type Health struct {
	latestNonErrorTimestamp time.Time
	latestErrorTimestamp    time.Time
	latestBusyTimestamp     time.Time
	timestampMutex          sync.RWMutex

	initialDataReady atomic.Bool
}

func New() *Health {
	return &Health{}
}

// SetInitialDataReady marks that all initial external data has been loaded.
// Until this is called, IsReady will report the service as not ready.
func (h *Health) SetInitialDataReady() {
	h.initialDataReady.Store(true)
}

func (h *Health) UpdateLatestTimestamps(nonErrorTimestamp *time.Time, errorTimestamp *time.Time, busyTimestamp *time.Time) {
	h.timestampMutex.Lock()
	if nonErrorTimestamp != nil && nonErrorTimestamp.After(h.latestNonErrorTimestamp) {
		h.latestNonErrorTimestamp = *nonErrorTimestamp
	}
	if errorTimestamp != nil && errorTimestamp.After(h.latestErrorTimestamp) {
		h.latestErrorTimestamp = *errorTimestamp
	}
	if busyTimestamp != nil && busyTimestamp.After(h.latestBusyTimestamp) {
		h.latestBusyTimestamp = *busyTimestamp
	}
	h.timestampMutex.Unlock()
}

func (h *Health) CompleteRequest(ctxWithDeadline context.Context, doneChan chan int) int {
	select {
	case reqStatus := <-doneChan: // Request completed.
		return reqStatus
	case <-ctxWithDeadline.Done(): // Request timed out.
		now := time.Now()
		h.UpdateLatestTimestamps(nil, nil, &now) // Busy.
		return -1
	}
}

func (h *Health) IsAlive(ctx *fasthttp.RequestCtx) bool {
	h.timestampMutex.RLock()
	nonErrorTimestamp := h.latestNonErrorTimestamp
	errorTimestamp := h.latestErrorTimestamp
	h.timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_non_error", nonErrorTimestamp),
		zap.Time("latest_error", errorTimestamp),
	})
	return !nonErrorTimestamp.Before(errorTimestamp)
}

func (h *Health) IsReady(ctx *fasthttp.RequestCtx, cfg *config.Settings) bool {
	if !h.initialDataReady.Load() {
		ctx.SetUserValue("zap_fields", []zap.Field{
			zap.Bool("initial_data_ready", false),
		})
		return false
	}

	h.timestampMutex.RLock()
	busyTimestamp := h.latestBusyTimestamp
	h.timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_busy", busyTimestamp),
	})
	return busyTimestamp.Add(cfg.Server.RememberBusyTimeout).Before(time.Now())
}
