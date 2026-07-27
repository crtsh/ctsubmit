package monitor

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	// Blank import to trigger loglists.init(), which calls ctloglists.LoadLogLists()
	// before monitor.init() populates backoff maps from CrtshV3Active.
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

// anyBackoffURL returns a URL from the init()-populated backoff maps.
func anyBackoffURL() string {
	for url := range backoffBadResponse {
		return url
	}
	return ""
}

func TestRecordAndGetBadResponseBackoff(t *testing.T) {
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	// Reset the entry to ensure a clean state.
	mutexBadResponse.Lock()
	backoffBadResponse[url] = &backoffEntry{}
	mutexBadResponse.Unlock()

	if d, _ := GetBadResponseBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	RecordBadResponse(url, fmt.Errorf("test error"))

	d, reason := GetBadResponseBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordBadResponse")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecordAndGetTimeoutBackoff(t *testing.T) {
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	mutexTimeout.Lock()
	backoffTimeout[url] = &backoffEntry{}
	mutexTimeout.Unlock()

	if d, _ := GetTimeoutBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	RecordTimeout(url, fmt.Errorf("timeout"))

	d, reason := GetTimeoutBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordTimeout")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecordAndGetSlowResponseBackoff(t *testing.T) {
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	mutexSlowResponse.Lock()
	backoffSlowResponse[url] = &backoffEntry{}
	mutexSlowResponse.Unlock()

	if d, _ := GetSlowResponseBackoff(url); d > 0 {
		t.Fatalf("expected no backoff initially, got %v", d)
	}

	RecordSlowResponse(url)

	d, reason := GetSlowResponseBackoff(url)
	if d <= 0 {
		t.Fatal("expected positive backoff after RecordSlowResponse")
	}
	if reason == "" {
		t.Fatal("expected non-empty reason")
	}
}

func TestRecord5xxWithRetryAfter(t *testing.T) {
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	mutex5xx.Lock()
	backoff5xx[url] = &backoffEntry{}
	mutex5xx.Unlock()

	resp := &http.Response{
		StatusCode: 503,
		Header:     http.Header{"Retry-After": []string{"300"}},
	}
	Record5xxResponse(url, resp)

	d, reason, code := Get5xxBackoff(url)
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
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	mutex4xx.Lock()
	backoff4xx[url] = &backoffEntry{}
	mutex4xx.Unlock()

	resp := &http.Response{
		StatusCode: 429,
		Header:     http.Header{},
	}
	Record4xxResponse(url, resp)

	d, reason, code := Get4xxBackoff(url)
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
	unknownURL := "https://nonexistent.example.test/"

	if d, _ := GetBadResponseBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for bad response")
	}
	if d, _ := GetTimeoutBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for timeout")
	}
	if d, _, _ := Get5xxBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for 5xx")
	}
	if d, _, _ := Get4xxBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for 4xx")
	}
	if d, _ := GetSlowResponseBackoff(unknownURL); d != 0 {
		t.Fatal("unknown URL should return zero backoff for slow response")
	}
}

func TestRecordBadResponseUnknownURLReturnsFalse(t *testing.T) {
	if RecordBadResponse("https://nonexistent.example.test/", fmt.Errorf("err")) {
		t.Fatal("RecordBadResponse for unknown URL should return false")
	}
}

func TestBackoffDoesNotExtendWithEarlierDeadline(t *testing.T) {
	url := anyBackoffURL()
	if url == "" {
		t.Skip("no log URLs in backoff maps")
	}

	// Set a backoff far in the future.
	mutexBadResponse.Lock()
	backoffBadResponse[url] = &backoffEntry{
		BackoffUntil:  time.Now().Add(1 * time.Hour),
		BackoffPeriod: 1 * time.Hour,
	}
	mutexBadResponse.Unlock()

	d1, _ := GetBadResponseBackoff(url)

	// Record again — the default backoff period is shorter (1 minute),
	// so the deadline should NOT be shortened.
	RecordBadResponse(url, fmt.Errorf("err"))

	d2, _ := GetBadResponseBackoff(url)
	if d2 < d1-time.Second {
		t.Fatal("backoff deadline should not be shortened by a shorter period")
	}
}
