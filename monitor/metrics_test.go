package monitor

import (
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
)

func TestRecentOutcomeCounts(t *testing.T) {
	m := New(config.MustLoad())
	url := "https://outcome-counts.example.test/"

	m.RecordSubmissionOutcome(url, "success")
	m.RecordSubmissionOutcome(url, "http_error")
	m.RecordSubmissionOutcome(url, "cancelled") // ignored: no response was received.

	successes, failures := m.GetRecentOutcomeCounts(url)
	if successes != 1 {
		t.Errorf("successes: got %d, want 1", successes)
	}
	if failures != 1 {
		t.Errorf("failures: got %d, want 1", failures)
	}
}

func TestRecentOutcomeCountsUnknownURL(t *testing.T) {
	m := New(config.MustLoad())
	successes, failures := m.GetRecentOutcomeCounts("https://never-recorded.example.test/")
	if successes != 0 || failures != 0 {
		t.Fatalf("unknown URL: got (%d, %d), want (0, 0)", successes, failures)
	}
}

func TestAvgResponseTime(t *testing.T) {
	m := New(config.MustLoad())
	url := "https://avg-response.example.test/"

	if _, ok := m.GetAvgResponseTime(url); ok {
		t.Fatal("expected no average before any samples are recorded")
	}

	m.RecordSubmissionResponseTime(url, 100*time.Millisecond)
	m.RecordSubmissionResponseTime(url, 300*time.Millisecond)

	avg, ok := m.GetAvgResponseTime(url)
	if !ok {
		t.Fatal("expected an average after recording samples")
	}
	if avg != 200*time.Millisecond {
		t.Fatalf("avg: got %v, want 200ms", avg)
	}
}
