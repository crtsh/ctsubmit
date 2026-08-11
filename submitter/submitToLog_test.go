package submitter

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/crtsh/ctloglists"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
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
