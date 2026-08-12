package submitter

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"

	ctgo "github.com/google/certificate-transparency-go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSubmitPropagatesContextCancellationToLogRequest(t *testing.T) {
	requestCancelled := make(chan struct{})
	cfg := config.MustLoad()
	s := New(cfg, logger.Logger, monitor.New(cfg))
	s.client = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			close(requestCancelled)
			return nil, req.Context().Err()
		}),
	}

	submissionRequest := NewSubmissionRequest()
	submissionRequest.Chain = [][]byte{[]byte("certificate")}

	strategy := []StrategyMember{{
		SubmissionURL: "https://example.test",
		Operator:      "test operator",
		LogType:       LOGTYPE_RFC6962,
		Bucket:        NEUTRAL,
	}}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, _, err := s.submit(ctx, submissionRequest, strategy, nil, ctgo.X509LogEntryType, []byte("certificate"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("submit() error = %v, want %v", err, context.DeadlineExceeded)
	}

	select {
	case <-requestCancelled:
	case <-time.After(time.Second):
		t.Fatal("log request context was not cancelled")
	}
}
