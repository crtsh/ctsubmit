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

var (
	latestNonErrorTimestamp time.Time
	latestErrorTimestamp    time.Time
	latestBusyTimestamp     time.Time
	timestampMutex          sync.RWMutex

	initialDataReady atomic.Bool
)

// SetInitialDataReady marks that all initial external data has been loaded.
// Until this is called, IsReady will report the service as not ready.
func SetInitialDataReady() {
	initialDataReady.Store(true)
}

func UpdateLatestTimestamps(nonErrorTimestamp *time.Time, errorTimestamp *time.Time, busyTimestamp *time.Time) {
	timestampMutex.Lock()
	if nonErrorTimestamp != nil && nonErrorTimestamp.After(latestNonErrorTimestamp) {
		latestNonErrorTimestamp = *nonErrorTimestamp
	}
	if errorTimestamp != nil && errorTimestamp.After(latestErrorTimestamp) {
		latestErrorTimestamp = *errorTimestamp
	}
	if busyTimestamp != nil && busyTimestamp.After(latestBusyTimestamp) {
		latestBusyTimestamp = *busyTimestamp
	}
	timestampMutex.Unlock()
}

func CompleteRequest(ctxWithDeadline context.Context, doneChan chan int) int {
	select {
	case reqStatus := <-doneChan: // Request completed.
		return reqStatus
	case <-ctxWithDeadline.Done(): // Request timed out.
		now := time.Now()
		UpdateLatestTimestamps(nil, nil, &now) // Busy.
		return -1
	}
}

func IsAlive(ctx *fasthttp.RequestCtx) bool {
	timestampMutex.RLock()
	nonErrorTimestamp := latestNonErrorTimestamp
	errorTimestamp := latestErrorTimestamp
	timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_non_error", nonErrorTimestamp),
		zap.Time("latest_error", errorTimestamp),
	})
	return !nonErrorTimestamp.Before(errorTimestamp)
}

func IsReady(ctx *fasthttp.RequestCtx) bool {
	if !initialDataReady.Load() {
		ctx.SetUserValue("zap_fields", []zap.Field{
			zap.Bool("initial_data_ready", false),
		})
		return false
	}

	timestampMutex.RLock()
	busyTimestamp := latestBusyTimestamp
	timestampMutex.RUnlock()

	ctx.SetUserValue("zap_fields", []zap.Field{
		zap.Time("latest_busy", busyTimestamp),
	})
	return busyTimestamp.Add(config.Config.Server.RememberBusyTimeout).Before(time.Now())
}
