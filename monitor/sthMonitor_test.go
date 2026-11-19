package monitor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"

	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

func TestCheckpointKeyName(t *testing.T) {
	tests := map[string]string{
		"https://log.example.com/":     "log.example.com",
		"https://log.example.com/2026": "log.example.com/2026",
		"http://127.0.0.1:6962/":       "127.0.0.1:6962",
		"http://127.0.0.1:6962":        "127.0.0.1:6962",
		"log.example.com/":             "log.example.com",
	}

	for submissionURL, want := range tests {
		if got := checkpointKeyName(submissionURL); got != want {
			t.Errorf("checkpointKeyName(%q) = %q, want %q", submissionURL, got, want)
		}
	}
}

func TestFetchSTHRecordsFetchTimeSeparately(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sigVerifier, err := ctgo.NewSignatureVerifier(key.Public())
	if err != nil {
		t.Fatal(err)
	}

	sthTimestamp := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
	sth := ctgo.SignedTreeHead{
		Version:   ctgo.V1,
		TreeSize:  42,
		Timestamp: uint64(sthTimestamp.UnixMilli()),
	}
	sigInput, err := ctgo.SerializeSTHSignatureInput(sth)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(sigInput)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	treeHeadSignature, err := tls.Marshal(ctgo.DigitallySigned{
		Algorithm: tls.SignatureAndHashAlgorithm{Hash: tls.SHA256, Signature: tls.ECDSA},
		Signature: sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(ctgo.GetSTHResponse{
		TreeSize:          sth.TreeSize,
		Timestamp:         sth.Timestamp,
		SHA256RootHash:    make([]byte, sha256.Size),
		TreeHeadSignature: treeHeadSignature,
	})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	m := New(config.MustLoad())
	logURL := srv.URL + "/"
	sd := &STHData{IsRFC6962Log: true, SigVerifier: sigVerifier, SubmissionURL: logURL}
	m.sthData[logURL] = sd

	before := time.Now()
	m.fetchSTH(logURL, sd)

	got, ok := m.GetSTHData(logURL)
	if !ok || got.Timestamp == nil || got.LastFetched == nil {
		t.Fatalf("fetchSTH did not populate STH data: %+v", got)
	}
	if got.TreeSize != sth.TreeSize {
		t.Errorf("TreeSize = %d, want %d", got.TreeSize, sth.TreeSize)
	}
	if !got.Timestamp.Equal(sthTimestamp) {
		t.Errorf("Timestamp = %v, want %v", *got.Timestamp, sthTimestamp)
	}
	if got.LastFetched.Before(before) {
		t.Errorf("LastFetched = %v, want a time no earlier than %v", *got.LastFetched, before)
	}
}
