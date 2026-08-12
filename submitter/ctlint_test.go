package submitter

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/pki"

	ctgo "github.com/google/certificate-transparency-go"
)

// oidExtensionCTSCT is the RFC 6962 SignedCertificateTimestampList extension OID.
var oidExtensionCTSCT = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// leafTBSWithUnknownLogSCT builds the raw TBSCertificate of a Server
// Authentication leaf certificate carrying an embedded SCT list with a single
// SCT from a log that is absent from ctlint's bundled production log lists.
func leafTBSWithUnknownLogSCT(t *testing.T) []byte {
	t.Helper()

	var unknownLogID [sha256.Size]byte
	for i := range unknownLogID {
		unknownLogID[i] = 0xEE
	}
	sct := &ctgo.SignedCertificateTimestamp{
		SCTVersion: ctgo.V1,
		LogID:      ctgo.LogID{KeyID: unknownLogID},
		Timestamp:  uint64(time.Now().UnixMilli()),
	}
	sctListBytes, err := pki.MarshalSCTList([]*ctgo.SignedCertificateTimestamp{sct})
	if err != nil {
		t.Fatalf("MarshalSCTList: %v", err)
	}
	// The extension value is the TLS-encoded SCT list wrapped in an OCTET STRING.
	sctExtValue, err := asn1.Marshal(sctListBytes)
	if err != nil {
		t.Fatalf("marshal SCT extension value: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		ExtKeyUsage:  []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtensionCTSCT, Value: sctExtValue},
		},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := stdx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert.RawTBSCertificate
}

func findingList(rs []CTLintResult) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Finding
	}
	return out
}

func containsFinding(rs []CTLintResult, substr string) bool {
	for _, r := range rs {
		if strings.Contains(r.Finding, substr) {
			return true
		}
	}
	return false
}

// TestRunCTLintTestLogSuppression drives runCTLint end-to-end with a certificate
// whose SCT is from an unknown (test) log, and checks that the production-log
// findings are surfaced normally but suppressed when testMode is set.
func TestRunCTLintTestLogSuppression(t *testing.T) {
	tbs := leafTBSWithUnknownLogSCT(t)
	// The issuer SPKI value is irrelevant here: an unknown-log SCT short-circuits
	// in ctlint before any signature verification is attempted.
	var issuerSPKI [sha256.Size]byte

	prod := runCTLint(tbs, &issuerSPKI, false)
	test := runCTLint(tbs, &issuerSPKI, true)

	// Sanity: ctlint recognized the embedded SCT list (a finding that is never suppressed).
	if !containsFinding(prod, "with embedded SCT list identified") {
		t.Fatalf("expected ctlint to identify the embedded SCT list; got %v", findingList(prod))
	}

	// Production mode surfaces the production-log-approval findings.
	for _, w := range []string{
		"no SCTs from logs currently approved by the",
		"SCT is from an unknown log",
	} {
		if !containsFinding(prod, w) {
			t.Errorf("production mode: expected a finding containing %q; got %v", w, findingList(prod))
		}
	}

	// Test mode suppresses every production-log finding...
	for _, r := range test {
		if isTestLogFinding(r.Finding) {
			t.Errorf("test mode should have suppressed finding %q", r.Finding)
		}
	}
	// ...while retaining the non-suppressed findings.
	if !containsFinding(test, "with embedded SCT list identified") {
		t.Errorf("test mode should retain the embedded-SCT-list finding; got %v", findingList(test))
	}
	if len(test) >= len(prod) {
		t.Errorf("test mode (%d findings) should have fewer findings than production mode (%d)", len(test), len(prod))
	}
}

// TestIsTestLogFinding pins the suppression predicate: production-log findings
// are suppressed, and structural/per-SCT findings are retained.
func TestIsTestLogFinding(t *testing.T) {
	suppressed := []string{
		"SCT list contains no SCTs from logs currently approved by the Chrome CT Policy",
		"SCT list contains no SCTs from logs currently approved by the Apple CT Policy",
		"SCT list contains no SCTs from logs currently approved by the Mozilla CT Policy",
		"SCT list contains no SCTs from logs currently approved by the Mark Certificate Guidelines",
		"SCT list contains fewer approved SCTs than required by the Chrome CT Policy",
		"SCT list satisfies the Chrome CT Policy using at least 1 SCT from a Qualified log that is not yet Usable",
		"SCT list satisfies the Mozilla CT Policy using at least 1 SCT from an Admissible log that is not yet broadly usable",
		"SCT list contains SCTs from fewer log operators than required by the Apple CT Policy",
		"SCT list contains fewer SCTs from RFC6962-compliant logs than required by the Apple CT Policy",
		"Certificate expires outside log's temporal interval",
		"SCT is from an unknown log",
	}
	for _, f := range suppressed {
		if !isTestLogFinding(f) {
			t.Errorf("expected %q to be suppressed in test mode", f)
		}
	}

	retained := []string{
		"Server Authentication Certificate with embedded SCT list identified",
		"SCT list extension could not be parsed",
		"SCT list contains trailing data",
		"SCTs could not be parsed from SCT list",
		"Multiple SCT list extensions are present",
		"Precertificate 'poison' extension is present",
		"OCSP SCT list extension is present",
		"SCT version is not V1",
		"SCT timestamp is in the future",
		"SCT has an invalid signature",
		"SCT has a valid signature",
		"Certificate notBefore timestamp >48 hours older than at least one embedded SCT",
	}
	for _, f := range retained {
		if isTestLogFinding(f) {
			t.Errorf("expected %q to be retained (not suppressed) in test mode", f)
		}
	}
}

func TestRunCTLintDummyCertError(t *testing.T) {
	// An unparseable TBSCertificate makes MakeDummyCertificate fail, producing a
	// single fatal finding.
	res := runCTLint([]byte{0x00}, nil, false)
	if len(res) != 1 || res[0].Severity != "fatal" {
		t.Fatalf("expected a single fatal finding, got %+v", res)
	}
}
