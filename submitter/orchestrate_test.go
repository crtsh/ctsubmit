package submitter

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestSubmitPropagatesContextCancellationToLogRequest(t *testing.T) {
	requestCancelled := make(chan struct{})
	originalHTTPClient := submissionHTTPClient
	submissionHTTPClient = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			close(requestCancelled)
			return nil, req.Context().Err()
		}),
	}
	defer func() {
		submissionHTTPClient = originalHTTPClient
	}()

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

	_, _, err := submissionRequest.submit(ctx, strategy, nil, ctgo.X509LogEntryType, []byte("certificate"))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("submit() error = %v, want %v", err, context.DeadlineExceeded)
	}

	select {
	case <-requestCancelled:
	case <-time.After(time.Second):
		t.Fatal("log request context was not cancelled")
	}
}
