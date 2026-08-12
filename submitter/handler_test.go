package submitter

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/monitor"

	x509 "github.com/google/certificate-transparency-go/x509"
)

// selfSignedDER returns the DER of an ECDSA-P256 self-signed certificate with
// the given validity window.
func selfSignedDER(t *testing.T, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestDetermineSubmissionRequirements(t *testing.T) {
	der := selfSignedDER(t, time.Now().Add(-time.Hour), time.Now().Add(365*24*time.Hour))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Default: policy-compliant TLS certificate.
	sr := NewSubmissionRequest()
	if ll := sr.determineSubmissionRequirements(cert); ll == nil {
		t.Fatal("expected a base log list")
	}
	if !sr.RequireAtLeastOneRFC6962SCT {
		t.Error("expected the RFC6962 requirement to be set for a policy-compliant TLS cert")
	}
	if sr.Operators < 2 {
		t.Errorf("expected >= 2 operators, got %d", sr.Operators)
	}
	// A >180-day validity requires 3 SCTs.
	if sr.SCTs < 3 {
		t.Errorf("expected >= 3 SCTs for a long-lived cert, got %d", sr.SCTs)
	}

	// Test-logs and non-policy-compliant branches select different base lists.
	srTest := NewSubmissionRequest()
	srTest.TestLogs = true
	if ll := srTest.determineSubmissionRequirements(cert); ll == nil {
		t.Fatal("expected the test log list")
	}
	srAll := NewSubmissionRequest()
	srAll.PolicyCompliant = false
	if ll := srAll.determineSubmissionRequirements(cert); ll == nil {
		t.Fatal("expected the active log list")
	}
}

func TestDetermineCompatibleLogs(t *testing.T) {
	// An expired cert under policy compliance is rejected outright.
	expiredDER := selfSignedDER(t, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	expiredCert, err := x509.ParseCertificate(expiredDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := determineCompatibleLogs(expiredCert, NewSubmissionRequest(), loglists.UsableTLSLogs); err == nil {
		t.Error("expected an error for an expired cert under policy compliance")
	}

	// A self-signed cert doesn't chain to any accepted root, so no logs are compatible.
	validDER := selfSignedDER(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	validCert, err := x509.ParseCertificate(validDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	sr := NewSubmissionRequest()
	sr.Chain = [][]byte{validDER}
	if _, err := determineCompatibleLogs(validCert, sr, loglists.UsableTLSLogs); err == nil {
		t.Error("expected a 'not enough compatible logs' error for a self-signed cert")
	}
}

func TestHandle(t *testing.T) {
	cfg := config.MustLoad()
	s := New(cfg, logger.Logger, monitor.New(cfg))
	der := selfSignedDER(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))

	// A self-signed cert has no compatible logs, so Handle errors before any
	// network I/O (nothing is submitted).
	addChain := NewSubmissionRequest()
	addChain.Chain = [][]byte{der}
	if _, err := s.Handle(context.Background(), endpoint.ENDPOINT_ADDCHAIN, addChain); err == nil {
		t.Error("expected an error (no compatible logs) from Handle")
	}

	// A certificate submitted to add-pre-chain is rejected early.
	addPreChain := NewSubmissionRequest()
	addPreChain.Chain = [][]byte{der}
	if _, err := s.Handle(context.Background(), endpoint.ENDPOINT_ADDPRECHAIN, addPreChain); err == nil {
		t.Error("expected an error for a certificate submitted to add-pre-chain")
	}

	// An empty chain is rejected.
	if _, err := s.Handle(context.Background(), endpoint.ENDPOINT_ADDCHAIN, NewSubmissionRequest()); err == nil {
		t.Error("expected an error for an empty chain")
	}
}

// markCertDER returns the DER of a self-signed certificate carrying the BIMI
// (Mark Certificate) extended key usage OID.
func markCertDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "mark.example"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(90 * 24 * time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 31}}, // BIMI id-kp-BrandIndicatorforMessageIdentification.
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestDetermineSubmissionRequirementsMarkCertificate(t *testing.T) {
	cert, err := x509.ParseCertificate(markCertDER(t))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	sr := NewSubmissionRequest()
	ll := sr.determineSubmissionRequirements(cert)
	if ll != loglists.UsableBIMILogs {
		t.Error("a Mark Certificate should select the BIMI log list")
	}
	if sr.RequireAtLeastOneRFC6962SCT {
		t.Error("a Mark Certificate should not enable the RFC6962 requirement")
	}
}

func TestDetermineSubmissionRequirementsShortLived(t *testing.T) {
	// A <=180-day validity under policy compliance requires exactly 2 SCTs.
	der := selfSignedDER(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	sr := NewSubmissionRequest()
	sr.determineSubmissionRequirements(cert)
	if sr.SCTs != 2 {
		t.Errorf("short-lived policy-compliant cert: got %d SCTs, want 2", sr.SCTs)
	}
}

func TestDetermineSubmissionRequirementsSCTsClampToOperators(t *testing.T) {
	der := selfSignedDER(t, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	// Non-policy-compliant so the SCT count is driven only by the operator clamp.
	sr := NewSubmissionRequest()
	sr.PolicyCompliant = false
	sr.Operators = 3
	sr.determineSubmissionRequirements(cert)
	if sr.SCTs < 3 {
		t.Errorf("SCTs should be clamped up to the operator count: got %d, want >= 3", sr.SCTs)
	}
}
