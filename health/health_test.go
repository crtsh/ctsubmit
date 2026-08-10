package health

import (
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func resetHealth() {
	timestampMutex.Lock()
	latestNonErrorTimestamp = time.Time{}
	latestErrorTimestamp = time.Time{}
	latestBusyTimestamp = time.Time{}
	timestampMutex.Unlock()
	initialDataReady.Store(false)
}

func TestIsReadyRequiresInitialData(t *testing.T) {
	resetHealth()
	ctx := &fasthttp.RequestCtx{}

	if IsReady(ctx) {
		t.Fatal("expected not ready before initial data is loaded")
	}

	SetInitialDataReady()
	if !IsReady(ctx) {
		t.Fatal("expected ready after initial data is loaded with no recent busy")
	}
}

func TestIsReadyReflectsRecentBusy(t *testing.T) {
	resetHealth()
	SetInitialDataReady()

	now := time.Now()
	UpdateLatestTimestamps(nil, nil, &now)

	ctx := &fasthttp.RequestCtx{}
	if IsReady(ctx) {
		t.Fatal("expected not ready immediately after a busy timestamp")
	}
}

func TestIsAlive(t *testing.T) {
	resetHealth()
	ctx := &fasthttp.RequestCtx{}

	// No error recorded: alive.
	if !IsAlive(ctx) {
		t.Fatal("expected alive when no error has been recorded")
	}

	// Latest error after latest non-error: not alive.
	errTime := time.Now()
	UpdateLatestTimestamps(nil, &errTime, nil)
	if IsAlive(ctx) {
		t.Fatal("expected not alive when latest error is after latest non-error")
	}

	// A newer non-error: alive again.
	okTime := errTime.Add(time.Second)
	UpdateLatestTimestamps(&okTime, nil, nil)
	if !IsAlive(ctx) {
		t.Fatal("expected alive when latest non-error is after latest error")
	}
}

func TestUpdateLatestTimestampsIsMonotonic(t *testing.T) {
	resetHealth()

	t1 := time.Now()
	UpdateLatestTimestamps(&t1, nil, nil)

	older := t1.Add(-time.Hour)
	UpdateLatestTimestamps(&older, nil, nil)

	timestampMutex.RLock()
	got := latestNonErrorTimestamp
	timestampMutex.RUnlock()
	if !got.Equal(t1) {
		t.Fatalf("timestamp moved backward: got %v, want %v", got, t1)
	}
}
