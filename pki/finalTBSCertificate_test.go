package pki

import (
	"math/big"
	"testing"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

// validRDNSequence returns a minimal DER-encoded RDN sequence for use as
// Issuer/Subject in test certificates.
func validRDNSequence(t *testing.T) asn1.RawValue {
	t.Helper()
	seq, err := asn1.Marshal(pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // CN
				Value: "test",
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal RDN: %v", err)
	}
	return asn1.RawValue{FullBytes: seq}
}

func makePrecertDER(t *testing.T, extraExtensions ...pkix.Extension) []byte {
	t.Helper()
	rdnSeq := validRDNSequence(t)
	tbs := TBSCertificate{
		Version:      2,
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // SHA256WithRSA
		},
		Issuer:   rdnSeq,
		Validity: validity{NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)},
		Subject:  rdnSeq,
		Extensions: append([]pkix.Extension{
			{Id: x509.OIDExtensionCTPoison, Critical: true, Value: []byte{0x05, 0x00}},
		}, extraExtensions...),
	}
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		SignatureValue: asn1.BitString{Bytes: []byte{0xff}, BitLength: 8},
	}
	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatalf("marshal precert: %v", err)
	}
	return der
}

func TestDetoxRemovesCTPoison(t *testing.T) {
	der := makePrecertDER(t)
	tbs, err := DetoxTBSCertificateFromPrecertificate(der)
	if err != nil {
		t.Fatalf("DetoxTBSCertificateFromPrecertificate: %v", err)
	}
	for _, ext := range tbs.Extensions {
		if ext.Id.Equal(x509.OIDExtensionCTPoison) {
			t.Fatal("CT Poison extension should have been removed")
		}
	}
}

func TestDetoxPreservesOtherExtensions(t *testing.T) {
	other := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // SAN OID
		Value: []byte{0x30, 0x00},
	}
	der := makePrecertDER(t, other)
	tbs, err := DetoxTBSCertificateFromPrecertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(tbs.Extensions) != 1 {
		t.Fatalf("expected 1 extension after detox, got %d", len(tbs.Extensions))
	}
	if !tbs.Extensions[0].Id.Equal(other.Id) {
		t.Fatal("remaining extension should be the non-poison one")
	}
}

func TestDetoxRejectsNoPoisonExtension(t *testing.T) {
	rdnSeq := validRDNSequence(t)
	tbs := TBSCertificate{
		Version:      2,
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		Issuer:   rdnSeq,
		Validity: validity{NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)},
		Subject:  rdnSeq,
	}
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		SignatureValue: asn1.BitString{Bytes: []byte{0xff}, BitLength: 8},
	}
	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DetoxTBSCertificateFromPrecertificate(der)
	if err == nil {
		t.Fatal("expected error for cert without CT Poison")
	}
}

func TestDetoxRejectsMultiplePoisonExtensions(t *testing.T) {
	rdnSeq := validRDNSequence(t)
	tbs := TBSCertificate{
		Version:      2,
		SerialNumber: big.NewInt(1),
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		Issuer:   rdnSeq,
		Validity: validity{NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)},
		Subject:  rdnSeq,
		Extensions: []pkix.Extension{
			{Id: x509.OIDExtensionCTPoison, Critical: true, Value: []byte{0x05, 0x00}},
			{Id: x509.OIDExtensionCTPoison, Critical: true, Value: []byte{0x05, 0x00}},
		},
	}
	cert := certificate{
		TBSCertificate: tbs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		},
		SignatureValue: asn1.BitString{Bytes: []byte{0xff}, BitLength: 8},
	}
	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DetoxTBSCertificateFromPrecertificate(der)
	if err == nil {
		t.Fatal("expected error for multiple CT Poison extensions")
	}
}

func TestDetoxRejectsTrailingData(t *testing.T) {
	der := makePrecertDER(t)
	der = append(der, 0x00, 0x01, 0x02) // append trailing garbage

	_, err := DetoxTBSCertificateFromPrecertificate(der)
	if err == nil {
		t.Fatal("expected error for trailing data after certificate")
	}
}

func TestProduceFinalTBSCertificateAppendsSCTExtension(t *testing.T) {
	der := makePrecertDER(t)
	tbs, err := DetoxTBSCertificateFromPrecertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	sctList := []byte{0x00, 0x02, 0x00, 0x00} // minimal fake SCT list
	finalDER, err := ProduceFinalTBSCertificate(tbs, sctList)
	if err != nil {
		t.Fatal(err)
	}
	if len(finalDER) == 0 {
		t.Fatal("expected non-empty final TBS certificate")
	}

	// Re-parse to verify the SCT extension is present.
	var finalTBS TBSCertificate
	if _, err := asn1.Unmarshal(finalDER, &finalTBS); err != nil {
		t.Fatalf("re-parse final TBS: %v", err)
	}
	found := false
	for _, ext := range finalTBS.Extensions {
		if ext.Id.Equal(x509.OIDExtensionCTSCT) {
			found = true
			if ext.Critical {
				t.Fatal("SCT extension must not be critical")
			}
		}
		if ext.Id.Equal(x509.OIDExtensionCTPoison) {
			t.Fatal("CT Poison should not be present in final TBS")
		}
	}
	if !found {
		t.Fatal("SCT extension not found in final TBS certificate")
	}
}

func TestProduceFinalTBSCertificatePreservesExistingExtensions(t *testing.T) {
	sanOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	der := makePrecertDER(t, pkix.Extension{
		Id:    sanOID,
		Value: []byte{0x30, 0x00},
	})
	tbs, err := DetoxTBSCertificateFromPrecertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	finalDER, err := ProduceFinalTBSCertificate(tbs, []byte{0x00})
	if err != nil {
		t.Fatal(err)
	}

	var finalTBS TBSCertificate
	if _, err := asn1.Unmarshal(finalDER, &finalTBS); err != nil {
		t.Fatal(err)
	}

	// Should have the SAN extension + the SCT extension.
	if len(finalTBS.Extensions) != 2 {
		t.Fatalf("expected 2 extensions, got %d", len(finalTBS.Extensions))
	}
	hasSAN, hasSCT := false, false
	for _, ext := range finalTBS.Extensions {
		if ext.Id.Equal(sanOID) {
			hasSAN = true
		}
		if ext.Id.Equal(x509.OIDExtensionCTSCT) {
			hasSCT = true
		}
	}
	if !hasSAN {
		t.Fatal("SAN extension missing")
	}
	if !hasSCT {
		t.Fatal("SCT extension missing")
	}
}
