package submitter

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/monitor"

	"github.com/crtsh/ctloglists"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"

	"go.uber.org/zap"
)

// testLeafEntry builds the LogEntry exactly as verifySCTSignature does, so the
// signature we create in the test matches what verification serializes.
func testLeafEntry(entryType ctgo.LogEntryType, entryData []byte, issuerSPKI *[sha256.Size]byte, timestamp uint64) ctgo.LogEntry {
	leaf := ctgo.MerkleTreeLeaf{
		Version:  ctgo.V1,
		LeafType: ctgo.TimestampedEntryLeafType,
		TimestampedEntry: &ctgo.TimestampedEntry{
			EntryType: entryType,
			Timestamp: timestamp,
		},
	}
	if entryType == ctgo.PrecertLogEntryType {
		leaf.TimestampedEntry.PrecertEntry = &ctgo.PreCert{
			IssuerKeyHash:  *issuerSPKI,
			TBSCertificate: entryData,
		}
	} else {
		leaf.TimestampedEntry.X509Entry = &ctgo.ASN1Cert{Data: entryData}
	}
	return ctgo.LogEntry{Leaf: leaf}
}

func makeSignedSCT(t *testing.T, priv *ecdsa.PrivateKey, logID [sha256.Size]byte, entryType ctgo.LogEntryType, entryData []byte, issuerSPKI *[sha256.Size]byte, timestamp uint64) *ctgo.SignedCertificateTimestamp {
	t.Helper()
	sct := &ctgo.SignedCertificateTimestamp{
		SCTVersion: ctgo.V1,
		LogID:      ctgo.LogID{KeyID: logID},
		Timestamp:  timestamp,
	}
	data, err := ctgo.SerializeSCTSignatureInput(*sct, testLeafEntry(entryType, entryData, issuerSPKI, timestamp))
	if err != nil {
		t.Fatalf("SerializeSCTSignatureInput: %v", err)
	}
	ds, err := tls.CreateSignature(*priv, tls.SHA256, data)
	if err != nil {
		t.Fatalf("CreateSignature: %v", err)
	}
	sct.Signature = ctgo.DigitallySigned(ds)
	return sct
}

// registerTestVerifier injects a signature verifier for logID into the shared
// ctloglists.LogSignatureVerifierMap. This mutates process-global state, so it
// relies on unique (random) log IDs and t.Cleanup to avoid interfering with
// other tests; do not run these tests in parallel without adding locking.
func registerTestVerifier(t *testing.T, logID [sha256.Size]byte, pub crypto.PublicKey) {
	t.Helper()
	sv, err := ctgo.NewSignatureVerifier(pub)
	if err != nil {
		t.Fatalf("NewSignatureVerifier: %v", err)
	}
	if ctloglists.LogSignatureVerifierMap == nil {
		ctloglists.LogSignatureVerifierMap = make(map[[sha256.Size]byte]*ctgo.SignatureVerifier)
	}
	ctloglists.LogSignatureVerifierMap[logID] = sv
	t.Cleanup(func() { delete(ctloglists.LogSignatureVerifierMap, logID) })
}

func randomLogID(t *testing.T) [sha256.Size]byte {
	t.Helper()
	var logID [sha256.Size]byte
	if _, err := rand.Read(logID[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return logID
}

func TestVerifySCTSignatureX509Success(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	registerTestVerifier(t, logID, &priv.PublicKey)

	entryData := []byte("fake-certificate-der")
	sct := makeSignedSCT(t, priv, logID, ctgo.X509LogEntryType, entryData, nil, uint64(time.Now().UnixMilli()))

	if err := verifySCTSignature(sct, nil, ctgo.X509LogEntryType, entryData); err != nil {
		t.Fatalf("expected valid X509 SCT signature, got error: %v", err)
	}
}

func TestVerifySCTSignaturePrecertSuccess(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	registerTestVerifier(t, logID, &priv.PublicKey)

	entryData := []byte("fake-tbs-certificate")
	issuerSPKI := sha256.Sum256([]byte("issuer-spki"))
	sct := makeSignedSCT(t, priv, logID, ctgo.PrecertLogEntryType, entryData, &issuerSPKI, uint64(time.Now().UnixMilli()))

	if err := verifySCTSignature(sct, &issuerSPKI, ctgo.PrecertLogEntryType, entryData); err != nil {
		t.Fatalf("expected valid precert SCT signature, got error: %v", err)
	}
}

func TestVerifySCTSignatureUnknownLog(t *testing.T) {
	// A LogID that was never registered in the verifier map.
	logID := randomLogID(t)
	sct := &ctgo.SignedCertificateTimestamp{SCTVersion: ctgo.V1, LogID: ctgo.LogID{KeyID: logID}}

	err := verifySCTSignature(sct, nil, ctgo.X509LogEntryType, []byte("data"))
	if err == nil || !strings.Contains(err.Error(), "unknown log") {
		t.Fatalf("expected an unknown-log error, got: %v", err)
	}
}

func TestVerifySCTSignatureWrongKey(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	// Register the verifier with a public key that does NOT match the signer.
	registerTestVerifier(t, logID, &other.PublicKey)

	entryData := []byte("fake-certificate-der")
	sct := makeSignedSCT(t, signer, logID, ctgo.X509LogEntryType, entryData, nil, uint64(time.Now().UnixMilli()))

	if err := verifySCTSignature(sct, nil, ctgo.X509LogEntryType, entryData); err == nil {
		t.Fatal("expected signature verification to fail with a mismatched key")
	}
}

func TestVerifySCTSignatureTamperedEntry(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logID := randomLogID(t)
	registerTestVerifier(t, logID, &priv.PublicKey)

	sct := makeSignedSCT(t, priv, logID, ctgo.X509LogEntryType, []byte("original-der"), nil, uint64(time.Now().UnixMilli()))

	// Verify against different entry data than what was signed.
	if err := verifySCTSignature(sct, nil, ctgo.X509LogEntryType, []byte("tampered-der")); err == nil {
		t.Fatal("expected signature verification to fail for tampered entry data")
	}
}

// timeoutError is a net.Error that reports a timeout.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

// errorReader fails on Read, to exercise the response-body read-error path.
type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

func TestProcessHTTPResponseFailures(t *testing.T) {
	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))
	const url = "https://process-test.example/"

	body := func(status int, s string) *http.Response {
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(s)), Header: http.Header{}}
	}

	cases := []struct {
		name string
		resp *http.Response
		err  error
	}{
		{"transport error", nil, errors.New("boom")},
		{"timeout error", nil, timeoutError{}},
		{"server error", body(500, ""), nil},
		{"client error", body(400, ""), nil},
		{"unexpected 3xx status", body(302, ""), nil},
		{"body read error", &http.Response{StatusCode: 200, Body: io.NopCloser(errorReader{}), Header: http.Header{}}, nil},
		{"invalid json", body(200, "not json"), nil},
		{"undecodable sct", body(200, "{}"), nil},
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
