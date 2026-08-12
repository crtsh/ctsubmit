package submitter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/monitor"

	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSubmitPropagatesContextCancellationToLogRequest(t *testing.T) {
	requestCancelled := make(chan struct{})
	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))
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

func TestSubmitAllLogsFail(t *testing.T) {
	// A log that always returns 500 drives the submission orchestration through
	// its failure and quorum-not-met paths without any real network dependency.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))

	sr := NewSubmissionRequest()
	sr.SCTs = 2
	sr.Operators = 2
	strategy := []StrategyMember{
		{SubmissionURL: srv.URL, Operator: "A", LogType: LOGTYPE_RFC6962, Bucket: NEUTRAL},
		{SubmissionURL: srv.URL, Operator: "B", LogType: LOGTYPE_RFC6962, Bucket: NEUTRAL},
	}

	responses, scts, err := s.submit(context.Background(), sr, strategy, nil, ctgo.X509LogEntryType, []byte("data"))
	if err == nil {
		t.Fatal("expected an error when every log fails")
	}
	if responses != nil || scts != nil {
		t.Errorf("expected no responses/scts on failure, got %d responses, %d scts", len(responses), len(scts))
	}
}

func TestSubmitNoEligibleLogs(t *testing.T) {
	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))

	sr := NewSubmissionRequest()
	// The only strategy member is excluded, so there are no eligible logs.
	strategy := []StrategyMember{{SubmissionURL: "https://excluded.example/", Operator: "A", Bucket: EXCLUDED}}
	if _, _, err := s.submit(context.Background(), sr, strategy, nil, ctgo.X509LogEntryType, []byte("data")); err == nil {
		t.Fatal("expected an error when no logs are eligible")
	}
}
