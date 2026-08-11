package monitor

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"

	// Blank import to trigger loglists.init(), which calls ctloglists.LoadLogLists()
	// before the Monitor populates its backoff maps from CrtshV3Active.
	_ "github.com/crtsh/ctsubmit/loglists"
)

func TestParseRetryAfterSeconds(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"120"}}}
	d := parseRetryAfter(resp)
	if d != 120*time.Second {
		t.Fatalf("expected 120s, got %v", d)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	future := time.Now().Add(5 * time.Minute).UTC().Format(time.RFC1123)
	resp := &http.Response{Header: http.Header{"Retry-After": []string{future}}}
	d := parseRetryAfter(resp)
	if d < 4*time.Minute || d > 6*time.Minute {
		t.Fatalf("expected ~5m, got %v", d)
	}
}

func TestParseRetryAfterEmpty(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	if d := parseRetryAfter(resp); d != 0 {
		t.Fatalf("expected 0, got %v", d)
	}
}

func TestParseRetryAfterInvalidString(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"not-a-number"}}}
	if d := parseRetryAfter(resp); d != 0 {
		t.Fatalf("expected 0 for invalid string, got %v", d)
	}
}

func TestParseRetryAfterPastDate(t *testing.T) {
	past := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC1123)
	resp := &http.Response{Header: http.Header{"Retry-After": []string{past}}}
	if d := parseRetryAfter(resp); d != 0 {
		t.Fatalf("expected 0 for past date, got %v", d)
	}
}

func TestParseRetryAfterZero(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"0"}}}
	if d := parseRetryAfter(resp); d != 0 {
		t.Fatalf("expected 0 for zero seconds, got %v", d)
	}
}

func TestParseRetryAfterNegative(t *testing.T) {
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"-10"}}}
	if d := parseRetryAfter(resp); d != 0 {
		t.Fatalf("expected 0 for negative seconds, got %v", d)
	}
}

// anyBackoffURL returns a URL from the Monitor's pre-populated backoff maps.
func anyBackoffURL(m *Monitor) string {
	for url := range m.backoffBadResponse {
		return url
	}
	return ""
}

func TestRecordAndGetBadResponseBackoff(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	// Reset the entry to ensure a clean state.
	m.mutexBadResponse.Lock()
	m.backoffBadResponse[url] = &backoffEntry{}
	m.mutexBadResponse.Unlock()

	if d, _ := m.GetBadResponseBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	m.RecordBadResponse(url, fmt.Errorf("test error"))

	d, reason := m.GetBadResponseBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordBadResponse")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecordAndGetTimeoutBackoff(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	m.mutexTimeout.Lock()
	m.backoffTimeout[url] = &backoffEntry{}
	m.mutexTimeout.Unlock()

	if d, _ := m.GetTimeoutBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	m.RecordTimeout(url, fmt.Errorf("timeout"))

	d, reason := m.GetTimeoutBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordTimeout")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecordAndGetSlowResponseBackoff(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	m.mutexSlowResponse.Lock()
	m.backoffSlowResponse[url] = &backoffEntry{}
	m.mutexSlowResponse.Unlock()

	if d, _ := m.GetSlowResponseBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	m.RecordSlowResponse(url)

	d, reason := m.GetSlowResponseBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordSlowResponse")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecord5xxWithRetryAfter(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	m.mutex5xx.Lock()
	m.backoff5xx[url] = &backoffEntry{}
	m.mutex5xx.Unlock()

	resp := &http.Response{
		StatusCode: 503,
		Header:     http.Header{"Retry-After": []string{"300"}},
	}
	m.Record5xxResponse(url, resp)

	d, reason, code := m.Get5xxBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after Record5xxResponse")
	}
	if code != 503 {
		t.Fatalf("expected status code 503, got %d", code)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecord4xxResponse(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	m.mutex4xx.Lock()
	m.backoff4xx[url] = &backoffEntry{}
	m.mutex4xx.Unlock()

	resp := &http.Response{
		StatusCode: 429,
		Header:     http.Header{},
	}
	m.Record4xxResponse(url, resp)

	d, reason, code := m.Get4xxBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after Record4xxResponse")
	}
	if code != 429 {
		t.Fatalf("expected status code 429, got %d", code)
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestGetBackoffUnknownURL(t *testing.T) {
	m := New(&config.Config)
	unknownURL := "https://nonexistent.example.test/"

	if d, _ := m.GetBadResponseBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for bad response")
	}
	if d, _ := m.GetTimeoutBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for timeout")
	}
	if d, _, _ := m.Get5xxBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for 5xx")
	}
	if d, _, _ := m.Get4xxBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for 4xx")
	}
	if d, _ := m.GetSlowResponseBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for slow response")
	}
}

func TestRecordBadResponseUnknownURLCreatesEntry(t *testing.T) {
	// A log URL that isn't in the pre-populated maps (e.g. a log added to the
	// list at runtime) should get a backoff entry created on first use, rather
	// than being silently dropped.
	m := New(&config.Config)
	url := "https://newly-added-log.example.test/"

	m.mutexBadResponse.Lock()
	delete(m.backoffBadResponse, url)
	m.mutexBadResponse.Unlock()

	if !m.RecordBadResponse(url, fmt.Errorf("err")) {
		t.Fatal("RecordBadResponse should create an entry and return true for an unknown URL")
	}

	if d, _ := m.GetBadResponseBackoff(url); d <= 0 {
		t.Fatal("expected positive backoff after RecordBadResponse created the entry")
	}
}

func TestBackoffDoesNotExtendWithEarlierDeadline(t *testing.T) {
	m := New(&config.Config)
	url := anyBackoffURL(m)
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	// Set a backoff far in the future.
	m.mutexBadResponse.Lock()
	m.backoffBadResponse[url] = &backoffEntry{
		BackoffUntil:  time.Now().Add(1 * time.Hour),
		BackoffPeriod: 1 * time.Hour,
	}
	m.mutexBadResponse.Unlock()

	d1, _ := m.GetBadResponseBackoff(url)

	// Record again — the default backoff period is shorter (1 minute),
	// so the deadline should NOT be shortened.
	m.RecordBadResponse(url, fmt.Errorf("err"))

	d2, _ := m.GetBadResponseBackoff(url)
	if d2 < d1-time.Second {
		t.Fatal("backoff deadline should not be shortened by a shorter period")
	}
}
