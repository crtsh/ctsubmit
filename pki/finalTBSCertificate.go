package pki

import (
	"fmt"
	"math/big"
	"time"

	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509/pkix"
)

type validity struct {
	NotBefore, NotAfter time.Time
}

type TBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	UniqueId           asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueId    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type certificate struct {
	TBSCertificate     TBSCertificate
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

func DetoxTBSCertificateFromPrecertificate(precertificate []byte) (*TBSCertificate, error) {
	var c certificate
	rest, err := asn1.Unmarshal(precertificate, &c)
	if err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("asn1.Unmarshal(precertificate) => trailing data")
	}

	// Find the CT Poison extension.
	poisonIdx := -1
	for i, extension := range c.TBSCertificate.Extensions {
		if extension.Id.Equal(x509.OIDExtensionCTPoison) {
			if poisonIdx != -1 {
				return nil, fmt.Errorf("multiple CT Poison extensions found")
			}
			poisonIdx = i
		}
	}
	if poisonIdx == -1 {
		return nil, fmt.Errorf("no CT Poison extension found")
	}

	// Remove the CT Poison extension.
	c.TBSCertificate.Extensions = append(c.TBSCertificate.Extensions[:poisonIdx], c.TBSCertificate.Extensions[poisonIdx+1:]...)

	return &c.TBSCertificate, nil
}

func ProduceFinalTBSCertificate(detoxedTBSCert *TBSCertificate, sctList []byte) ([]byte, error) {
	// Encode the SCT List extension.
	sctListEncoded, err := asn1.Marshal(asn1.RawValue{
		Tag:   asn1.TagOctetString,
		Bytes: sctList,
	})
	if err != nil {
		return nil, err
	}

	// Append the SCT List extension.
	detoxedTBSCert.Extensions = append(detoxedTBSCert.Extensions, pkix.Extension{
		Id:       x509.OIDExtensionCTSCT,
		Critical: false,
		Value:    sctListEncoded,
	})

	// Re-encode the modified TBSCertificate.
	finalTBSCertificate, err := asn1.Marshal(*detoxedTBSCert)
	if err != nil {
		return nil, err
	}

	return finalTBSCertificate, nil
}
