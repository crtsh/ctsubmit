package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedTBS returns the raw TBSCertificate of a freshly generated,
// ECDSA-P256 self-signed certificate (signature algorithm ecdsa-with-SHA256).
func selfSignedTBS(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dummy.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert.RawTBSCertificate
}

func TestMakeDummyCertificate(t *testing.T) {
	cert, err := MakeDummyCertificate(selfSignedTBS(t))
	if err != nil {
		t.Fatalf("MakeDummyCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("MakeDummyCertificate returned a nil certificate")
	}
}

func TestMakeDummyCertificateInvalidInput(t *testing.T) {
	if _, err := MakeDummyCertificate([]byte{0x00}); err == nil {
		t.Fatal("expected an error for an invalid TBSCertificate input")
	}
}
