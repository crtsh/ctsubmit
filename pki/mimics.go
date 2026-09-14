package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/crtsh/ctsubmit/loglists"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
)

func init() {
	loglists.RegisterLogName(mimic1LogID.KeyID, "", "Mimic 1")
	loglists.RegisterLogName(mimic2LogID.KeyID, "", "Mimic 2")
}

// Matches https://googlechrome.github.io/CertificateTransparency/mimics/mimic1.pem
var mimic1PrivateKey = mustParsePrivateKey("777B0EF312E25246B4B155DC4D80C75FF5A437DC84EDA21A67C0F9A55C769620")
var mimic1LogID = ctgo.LogID{
	KeyID: [sha256.Size]byte{
		0xF4, 0x41, 0x95, 0xD6, 0xF0, 0x0E, 0x2D, 0xB5, 0x54, 0x35, 0xCA, 0xDD, 0x57, 0x78, 0x92, 0xE5,
		0x3E, 0x15, 0xAD, 0x41, 0x70, 0x58, 0xF8, 0x78, 0xE1, 0x4F, 0xF6, 0xB9, 0x18, 0x74, 0x15, 0x89,
	},
}

// Matches https://googlechrome.github.io/CertificateTransparency/mimics/mimic2.pem
var mimic2PrivateKey = mustParsePrivateKey("6A88796F01A7682CE40DBBDD45F6C24ED02B0EEA13E659EF6704A227F963FF86")
var mimic2LogID = ctgo.LogID{
	KeyID: [sha256.Size]byte{
		0xB2, 0x2F, 0x7E, 0xDE, 0xB5, 0xAF, 0x6A, 0xFE, 0x50, 0x3D, 0xE0, 0x40, 0x81, 0xB2, 0xD7, 0x4C,
		0x12, 0x53, 0x84, 0x92, 0xFE, 0xDF, 0x2C, 0xB2, 0xA5, 0x26, 0x50, 0x3C, 0xEF, 0x53, 0xCE, 0xD2,
	},
}

// mustParsePrivateKey builds a P-256 key from its raw scalar, deriving the
// public key so we avoid the deprecated ecdsa X/Y/D fields.
func mustParsePrivateKey(hexD string) *ecdsa.PrivateKey {
	raw, err := hex.DecodeString(hexD)
	if err != nil {
		panic("bad private key hex: " + hexD)
	}
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		panic("invalid mimic private key: " + err.Error())
	}
	return key
}

func GenerateMimicSCTs(detoxedTBSCert []byte, sha256IssuerSPKI [sha256.Size]byte) ([]*ctgo.SignedCertificateTimestamp, error) {
	timestamp := uint64(time.Now().UnixMilli())

	sct1, err := buildMimicSCT(mimic1LogID, mimic1PrivateKey, timestamp, sha256IssuerSPKI, detoxedTBSCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mimic SCT 1: %v", err)
	}

	sct2, err := buildMimicSCT(mimic2LogID, mimic2PrivateKey, timestamp, sha256IssuerSPKI, detoxedTBSCert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mimic SCT 2: %v", err)
	}

	return []*ctgo.SignedCertificateTimestamp{sct1, sct2}, nil
}

func buildMimicSCT(mimicLogID ctgo.LogID, privateKey *ecdsa.PrivateKey, timestamp uint64, issuerKeyHash [sha256.Size]byte, tbsCert []byte) (*ctgo.SignedCertificateTimestamp, error) {
	// Build the SCT and its signature input per RFC 6962 section 3.2.
	sct := ctgo.SignedCertificateTimestamp{
		SCTVersion: ctgo.V1,
		LogID:      mimicLogID,
		Timestamp:  timestamp,
	}

	entry := ctgo.LogEntry{
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

	signatureInput, err := ctgo.SerializeSCTSignatureInput(sct, entry)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize SCT signature input: %w", err)
	}

	tlsSig, err := tls.CreateSignature(*privateKey, tls.SHA256, signatureInput)
	if err != nil {
		return nil, fmt.Errorf("failed to sign mimic SCT: %w", err)
	}
	sct.Signature = ctgo.DigitallySigned(tlsSig)

	return &sct, nil
}
