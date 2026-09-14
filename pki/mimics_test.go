package pki

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	ctgo "github.com/google/certificate-transparency-go"
)

// buildMimicEntry reconstructs the LogEntry that buildMimicSCT signs, so tests
// can verify the SCT signatures.
func buildMimicEntry(timestamp uint64, issuerKeyHash [sha256.Size]byte, tbsCert []byte) ctgo.LogEntry {
	return ctgo.LogEntry{
		Leaf: ctgo.MerkleTreeLeaf{
			Version:  ctgo.V1,
			LeafType: ctgo.TimestampedEntryLeafType,
			TimestampedEntry: &ctgo.TimestampedEntry{
				Timestamp: timestamp,
				EntryType: ctgo.PrecertLogEntryType,
				PrecertEntry: &ctgo.PreCert{
					IssuerKeyHash:  issuerKeyHash,
					TBSCertificate: tbsCert,
				},
			},
		},
	}
}

func verifyMimicSCT(t *testing.T, pubKey *ecdsa.PublicKey, sct *ctgo.SignedCertificateTimestamp, issuerKeyHash [sha256.Size]byte, tbsCert []byte) {
	t.Helper()
	verifier, err := ctgo.NewSignatureVerifier(pubKey)
	if err != nil {
		t.Fatalf("NewSignatureVerifier: %v", err)
	}
	entry := buildMimicEntry(sct.Timestamp, issuerKeyHash, tbsCert)
	if err := verifier.VerifySCTSignature(*sct, entry); err != nil {
		t.Fatalf("SCT signature failed to verify: %v", err)
	}
}

// TestMimicKeysMatchLogIDs confirms each private key's derived public key hashes
// to the corresponding log ID, i.e. the raw scalar was parsed into the intended
// key pair.
func TestMimicKeysMatchLogIDs(t *testing.T) {
	cases := []struct {
		name  string
		key   *ecdsa.PrivateKey
		logID ctgo.LogID
	}{
		{"mimic1", mimic1PrivateKey, mimic1LogID},
		{"mimic2", mimic2PrivateKey, mimic2LogID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spki, err := x509.MarshalPKIXPublicKey(&tc.key.PublicKey)
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey: %v", err)
			}
			got := sha256.Sum256(spki)
			if got != tc.logID.KeyID {
				t.Fatalf("log ID mismatch:\n got %x\nwant %x", got, tc.logID.KeyID)
			}
		})
	}
}

func TestGenerateMimicSCTs(t *testing.T) {
	var issuerKeyHash [sha256.Size]byte
	for i := range issuerKeyHash {
		issuerKeyHash[i] = byte(i)
	}
	tbsCert := []byte("test TBS certificate bytes")

	before := uint64(time.Now().UnixMilli())
	scts, err := GenerateMimicSCTs(tbsCert, issuerKeyHash)
	after := uint64(time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("GenerateMimicSCTs: %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("expected 2 SCTs, got %d", len(scts))
	}

	expected := []struct {
		logID ctgo.LogID
		key   *ecdsa.PublicKey
	}{
		{mimic1LogID, &mimic1PrivateKey.PublicKey},
		{mimic2LogID, &mimic2PrivateKey.PublicKey},
	}
	for i, sct := range scts {
		if sct.SCTVersion != ctgo.V1 {
			t.Errorf("SCT %d: version = %v, want V1", i, sct.SCTVersion)
		}
		if sct.LogID != expected[i].logID {
			t.Errorf("SCT %d: LogID = %x, want %x", i, sct.LogID.KeyID, expected[i].logID.KeyID)
		}
		if sct.Timestamp < before || sct.Timestamp > after {
			t.Errorf("SCT %d: timestamp %d outside [%d, %d]", i, sct.Timestamp, before, after)
		}
		if len(sct.Signature.Signature) == 0 {
			t.Errorf("SCT %d: empty signature", i)
		}
		verifyMimicSCT(t, expected[i].key, sct, issuerKeyHash, tbsCert)
	}

	// Both SCTs share the single generation timestamp.
	if scts[0].Timestamp != scts[1].Timestamp {
		t.Errorf("expected shared timestamp, got %d and %d", scts[0].Timestamp, scts[1].Timestamp)
	}
}

func TestBuildMimicSCT(t *testing.T) {
	var issuerKeyHash [sha256.Size]byte
	tbsCert := []byte("another TBS certificate")
	timestamp := uint64(1_700_000_000_000)

	sct, err := buildMimicSCT(mimic1LogID, mimic1PrivateKey, timestamp, issuerKeyHash, tbsCert)
	if err != nil {
		t.Fatalf("buildMimicSCT: %v", err)
	}
	if sct.Timestamp != timestamp {
		t.Errorf("timestamp = %d, want %d", sct.Timestamp, timestamp)
	}
	if sct.LogID != mimic1LogID {
		t.Errorf("LogID = %x, want %x", sct.LogID.KeyID, mimic1LogID.KeyID)
	}
	verifyMimicSCT(t, &mimic1PrivateKey.PublicKey, sct, issuerKeyHash, tbsCert)
}
