package health

import (
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"

	"github.com/valyala/fasthttp"
)

func TestIsReadyRequiresInitialData(t *testing.T) {
	h := New()
	ctx := &fasthttp.RequestCtx{}

	if h.IsReady(ctx, config.MustLoad()) {
		t.Fatal("expected not ready before initial data is loaded")
	}

	h.SetInitialDataReady()
	if !h.IsReady(ctx, config.MustLoad()) {
		t.Fatal("expected ready after initial data is loaded with no recent busy")
	}
}

func TestIsReadyReflectsRecentBusy(t *testing.T) {
	h := New()
	h.SetInitialDataReady()

	now := time.Now()
	h.UpdateLatestTimestamps(nil, nil, &now)

	ctx := &fasthttp.RequestCtx{}
	if h.IsReady(ctx, config.MustLoad()) {
		t.Fatal("expected not ready immediately after a busy timestamp")
	}
}

func TestIsAlive(t *testing.T) {
	h := New()
	ctx := &fasthttp.RequestCtx{}

	// No error recorded: alive.
	if !h.IsAlive(ctx) {
		t.Fatal("expected alive when no error has been recorded")
	}

	// Latest error after latest non-error: not alive.
	errTime := time.Now()
	h.UpdateLatestTimestamps(nil, &errTime, nil)
	if h.IsAlive(ctx) {
		t.Fatal("expected not alive when latest error is after latest non-error")
	}

	// A newer non-error: alive again.
	okTime := errTime.Add(time.Second)
	h.UpdateLatestTimestamps(&okTime, nil, nil)
	if !h.IsAlive(ctx) {
		t.Fatal("expected alive when latest non-error is after latest error")
	}
}

func TestUpdateLatestTimestampsIsMonotonic(t *testing.T) {
	h := New()

	t1 := time.Now()
	h.UpdateLatestTimestamps(&t1, nil, nil)

	older := t1.Add(-time.Hour)
	h.UpdateLatestTimestamps(&older, nil, nil)

	h.timestampMutex.RLock()
	got := h.latestNonErrorTimestamp
	h.timestampMutex.RUnlock()
	if !got.Equal(t1) {
		t.Fatalf("timestamp moved backward: got %v, want %v", got, t1)
	}
}
