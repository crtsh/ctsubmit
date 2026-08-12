package submitter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"

	ctgo "github.com/google/certificate-transparency-go"
)

func TestProcessHTTPResponseFailures(t *testing.T) {
	cfg := config.MustLoad()
	s := New(cfg, logger.Logger, monitor.New(cfg))
	const url = "https://process-test.example/"

	resp := func(status int, body string) *http.Response {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
	}

	cases := []struct {
		name string
		resp *http.Response
		err  error
	}{
		{"transport error", nil, errors.New("boom")},
		{"server error", resp(500, ""), nil},
		{"client error", resp(400, ""), nil},
		{"invalid json", resp(200, "not json"), nil},
		{"undecodable sct", resp(200, "{}"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := make(chan submissionEvent, 1)
			s.processHTTPResponse(0, url, tc.resp, tc.err, nil, ctgo.X509LogEntryType, nil, time.Millisecond, events)
			if ev := <-events; ev.eventType != eventFailure {
				t.Errorf("%s: got event %v, want eventFailure", tc.name, ev.eventType)
			}
		})
	}
}

func TestCancelledSubmissionOutcome(t *testing.T) {
	assertContains := func(t *testing.T, name, got, want string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: got %q, want it to contain %q", name, got, want)
		}
	}

	quorum, cancelQ := context.WithCancelCause(context.Background())
	cancelQ(errQuorumMet)
	assertContains(t, "quorum", cancelledSubmissionOutcome(quorum), "quorum")

	deadline, cancelD := context.WithCancelCause(context.Background())
	cancelD(context.DeadlineExceeded)
	assertContains(t, "deadline", cancelledSubmissionOutcome(deadline), "deadline")

	canceled, cancelC := context.WithCancelCause(context.Background())
	cancelC(context.Canceled)
	assertContains(t, "canceled", cancelledSubmissionOutcome(canceled), "cancelled")

	custom, cancelX := context.WithCancelCause(context.Background())
	cancelX(errors.New("some other cause"))
	assertContains(t, "custom", cancelledSubmissionOutcome(custom), "some other cause")

	// A context with no cause falls through to the default message.
	if got := cancelledSubmissionOutcome(context.Background()); got != "Cancelled" {
		t.Errorf("default: got %q, want \"Cancelled\"", got)
	}
}

func TestCompileRegexes(t *testing.T) {
	res := compileRegexes([]string{`^https://a/`, `b\.example`})
	if len(res) != 2 {
		t.Fatalf("compileRegexes: got %d, want 2", len(res))
	}
	if !res[0].MatchString("https://a/") || !res[1].MatchString("https://b.example/") {
		t.Error("compiled regexes did not match expected inputs")
	}
	if got := compileRegexes(nil); got != nil {
		t.Errorf("compileRegexes(nil): got %v, want nil", got)
	}
}
