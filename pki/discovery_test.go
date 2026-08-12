package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/crtsh/ctsubmit/loglists"
)

// makeCertDER creates an ECDSA-P256 certificate signed by the given parent
// (self-signed when parent is nil) and returns its DER encoding.
func makeCertDER(t *testing.T, tmpl *stdx509.Certificate, parent *stdx509.Certificate, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := parentKey
	signee := parent
	if signer == nil {
		signer = key
		signee = tmpl
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, signee, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der, key
}

func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "self.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := makeCertDER(t, tmpl, nil, nil)
	return der
}

func TestGenerateMimicSCTs(t *testing.T) {
	var issuerSPKI [sha256.Size]byte
	scts, err := GenerateMimicSCTs(selfSignedTBS(t), issuerSPKI)
	if err != nil {
		t.Fatalf("GenerateMimicSCTs: %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("expected 2 mimic SCTs, got %d", len(scts))
	}
	for i, sct := range scts {
		if sct == nil {
			t.Errorf("SCT %d is nil", i)
		}
	}
}

func TestDiscoverChain(t *testing.T) {
	der := selfSignedDER(t)

	// A self-signed cert whose AKI isn't in the optimal-parents table yields no
	// additional chain. This exercises contextIndex for each supported log list.
	if got := DiscoverChain([][]byte{der}, loglists.UsableTLSLogs); got != nil {
		t.Errorf("expected nil chain for an unknown self-signed cert, got %d entries", len(got))
	}
	if got := DiscoverChain([][]byte{der}, loglists.TestTLSLogs); got != nil {
		t.Errorf("expected nil chain for TestTLSLogs, got %d entries", len(got))
	}
	if got := DiscoverChain([][]byte{der}, loglists.UsableBIMILogs); got != nil {
		t.Errorf("expected nil chain for UsableBIMILogs, got %d entries", len(got))
	}

	// An unparseable certificate returns nil.
	if got := DiscoverChain([][]byte{{0x00, 0x01}}, loglists.UsableTLSLogs); got != nil {
		t.Errorf("expected nil chain for an invalid cert, got %d entries", len(got))
	}
}

func TestIsSelfSignedCert(t *testing.T) {
	// Self-signed: issuer equals subject.
	selfCert, err := stdx509.ParseCertificate(selfSignedDER(t))
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !isSelfSignedCert(selfCert) {
		t.Error("expected a self-signed certificate to be reported as self-signed")
	}

	// CA-signed leaf: issuer differs from subject and AKI differs from SKI.
	caTmpl := &stdx509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "ca.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{0x01, 0x02, 0x03, 0x04},
	}
	caDER, caKey := makeCertDER(t, caTmpl, nil, nil)
	caCert, err := stdx509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	leafTmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "leaf.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		SubjectKeyId: []byte{0x05, 0x06, 0x07, 0x08},
	}
	leafDER, _ := makeCertDER(t, leafTmpl, caCert, caKey)
	leafCert, err := stdx509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("ParseCertificate leaf: %v", err)
	}
	if isSelfSignedCert(leafCert) {
		t.Error("expected a CA-signed leaf to not be reported as self-signed")
	}
}
