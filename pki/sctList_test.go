package pki

import (
	"testing"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

func TestMarshalSCTListRoundTrip(t *testing.T) {
	sct := &ctgo.SignedCertificateTimestamp{
		SCTVersion: ctgo.V1,
		Timestamp:  12345,
	}
	data, err := MarshalSCTList([]*ctgo.SignedCertificateTimestamp{sct})
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty marshaled SCT list")
	}

	var parsed x509.SignedCertificateTimestampList
	if _, err := tls.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
	if len(parsed.SCTList) != 1 {
		t.Fatalf("expected 1 SCT in list, got %d", len(parsed.SCTList))
	}
}

func TestMarshalSCTListMultiple(t *testing.T) {
	scts := []*ctgo.SignedCertificateTimestamp{
		{SCTVersion: ctgo.V1, Timestamp: 100},
		{SCTVersion: ctgo.V1, Timestamp: 200},
		{SCTVersion: ctgo.V1, Timestamp: 300},
	}
	data, err := MarshalSCTList(scts)
	if err != nil {
		t.Fatal(err)
	}

	var parsed x509.SignedCertificateTimestampList
	if _, err := tls.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.SCTList) != 3 {
		t.Fatalf("expected 3 SCTs, got %d", len(parsed.SCTList))
	}
}

func TestMarshalSCTListEmpty(t *testing.T) {
	_, err := MarshalSCTList([]*ctgo.SignedCertificateTimestamp{})
	if err == nil {
		t.Fatal("MarshalSCTList([]) should error (TLS minlen:1 constraint)")
	}
}

func TestMarshalSCTListNil(t *testing.T) {
	_, err := MarshalSCTList(nil)
	if err == nil {
		t.Fatal("MarshalSCTList(nil) should error (TLS minlen:1 constraint)")
	}
}
