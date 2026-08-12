package submitter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

func TestSubmitReachesQuorum(t *testing.T) {
	// A log that returns a validly-signed SCT lets submit reach quorum, covering
	// the success paths of submit, submitToLog, and processHTTPResponse.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	registerTestVerifier(t, logID, &priv.PublicKey)

	entryData := []byte("leaf-certificate-der")
	sct := makeSignedSCT(t, priv, logID, ctgo.X509LogEntryType, entryData, nil, uint64(time.Now().UnixMilli()))
	respBody := addChainResponseBody(t, sct)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(respBody)
	}))
	defer srv.Close()

	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	strategy := []StrategyMember{{SubmissionURL: srv.URL, Operator: "A", LogType: LOGTYPE_RFC6962, Bucket: NEUTRAL}}

	responses, scts, err := s.submit(context.Background(), sr, strategy, nil, ctgo.X509LogEntryType, entryData)
	if err != nil {
		t.Fatalf("submit: unexpected error: %v", err)
	}
	if len(responses) != 1 || len(scts) != 1 {
		t.Fatalf("expected 1 response and 1 SCT, got %d and %d", len(responses), len(scts))
	}
}

func TestSubmitFailsOverToNextLog(t *testing.T) {
	// The first log fails, so submit must launch the next eligible log, which
	// succeeds. Exercises the failure -> startNextEligible -> success path.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	registerTestVerifier(t, logID, &priv.PublicKey)

	entryData := []byte("leaf-certificate-der")
	sct := makeSignedSCT(t, priv, logID, ctgo.X509LogEntryType, entryData, nil, uint64(time.Now().UnixMilli()))
	respBody := addChainResponseBody(t, sct)

	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failSrv.Close()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(respBody)
	}))
	defer okSrv.Close()

	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))
	sr := NewSubmissionRequest()
	sr.SCTs = 1
	sr.Operators = 1
	// Only one log starts in the initial batch (SCTs=1); the failing log is first.
	strategy := []StrategyMember{
		{SubmissionURL: failSrv.URL, Operator: "A", LogType: LOGTYPE_RFC6962, Bucket: NEUTRAL},
		{SubmissionURL: okSrv.URL, Operator: "B", LogType: LOGTYPE_RFC6962, Bucket: NEUTRAL},
	}

	responses, scts, err := s.submit(context.Background(), sr, strategy, nil, ctgo.X509LogEntryType, entryData)
	if err != nil {
		t.Fatalf("submit: unexpected error: %v", err)
	}
	if len(responses) != 1 || len(scts) != 1 {
		t.Fatalf("expected quorum from the failover log, got %d responses, %d scts", len(responses), len(scts))
	}
}
