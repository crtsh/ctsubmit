package submitter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/pki"

	"github.com/crtsh/ccadb_data"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

func Handler(ctx context.Context, apiEndpoint endpoint.Endpoint, submissionRequest *SubmissionRequest) (*SubmissionResponse, error) {
	// Check "chain" parameter is present and contains at least one certificate.
	if len(submissionRequest.Chain) == 0 {
		return nil, fmt.Errorf("Missing or empty 'chain' parameter")
	}

	// Parse the first certificate in the chain.
	cert, err := x509.ParseCertificate(submissionRequest.Chain[0])
	if err != nil {
		return nil, fmt.Errorf("Failed to parse first certificate: %v", err)
	}

	// Ensure appropriate input for add-chain vs add-pre-chain.
	var entryType ctgo.LogEntryType
	var entryData []byte
	var detoxedTBSCert *pki.TBSCertificate
	if cert.IsPrecertificate() {
		if apiEndpoint == endpoint.ENDPOINT_ADDCHAIN {
			return nil, fmt.Errorf("Precertificate submitted to add-chain endpoint")
		}

		entryType = ctgo.PrecertLogEntryType

		// Remove the CT Poison extension from the precertificate to produce the "detoxed" TBSCertificate.
		if detoxedTBSCert, err = pki.DetoxTBSCertificateFromPrecertificate(cert.Raw); err != nil {
			return nil, fmt.Errorf("Failed to detox precertificate: %v", err)
		}

		// Re-marshal the detoxed TBSCertificate.
		entryData, err = asn1.Marshal(*detoxedTBSCert)
		if err != nil {
			return nil, fmt.Errorf("failed to re-marshal TBSCertificate: %v", err)
		}

	} else {
		if apiEndpoint == endpoint.ENDPOINT_ADDPRECHAIN {
			return nil, fmt.Errorf("Certificate submitted to add-pre-chain endpoint")
		}

		entryType = ctgo.X509LogEntryType
		entryData = cert.Raw
	}

	// Determine which base log list to use for this submission request, and how many SCTs from how many log operators are required.
	baseLogList := submissionRequest.determineSubmissionRequirements(cert)

	// If requested, automatically discover the (rest of the) certificate chain.
	if submissionRequest.DiscoverChain {
		if discoveredChain := pki.DiscoverChain(submissionRequest.Chain, baseLogList); discoveredChain != nil {
			submissionRequest.Chain = discoveredChain
		}
	}

	// Determine which logs from the base log list are compatible with the certificate and submission request.
	compatibleLogList, err := determineCompatibleLogs(cert, submissionRequest, baseLogList)
	if err != nil {
		return nil, err
	}

	// Strategize which logs to attempt submission to, in which order.
	strategy := devizeSubmissionStrategy(compatibleLogList, entryType)

	// Compute or lookup the issuer certificate's SPKI SHA-256 hash.
	var sha256IssuerSPKI *[sha256.Size]byte
	if len(submissionRequest.Chain) > 1 {
		issuer, err := x509.ParseCertificate(submissionRequest.Chain[1])
		if err != nil {
			return nil, fmt.Errorf("Failed to parse issuer certificate: %v", err)
		}
		hash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		sha256IssuerSPKI = &hash
	} else {
		if hash, found := ccadb_data.GetIssuerSPKISHA256ByKeyIdentifier(base64.StdEncoding.EncodeToString(cert.AuthorityKeyId)); found {
			sha256IssuerSPKI = &hash
		}
	}

	// Submit to the logs.
	submissionResponse := &SubmissionResponse{}
	var scts []*ctgo.SignedCertificateTimestamp
	submissionResponse.LogResponse, scts, err = submissionRequest.submit(ctx, strategy, sha256IssuerSPKI, entryType, entryData)
	if err != nil {
		return nil, fmt.Errorf("Submission failed: %v", err)
	}

	// If requested, generate mimic SCTs.
	if submissionRequest.Mimics && sha256IssuerSPKI != nil {
		mimicSCTs, err := pki.GenerateMimicSCTs(entryData, *sha256IssuerSPKI)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate mimic SCTs: %v", err)
		}

		// Append the mimic SCTs to the SCT list to be embedded in the final TBSCertificate.
		scts = append(scts, mimicSCTs...)

		// Include the mimic SCTs in the response's LogResponse.
		for _, mimicSCT := range mimicSCTs {
			sig, err := tls.Marshal(mimicSCT.Signature)
			if err != nil {
				return nil, fmt.Errorf("Failed to marshal mimic SCT signature: %v", err)
			}
			submissionResponse.LogResponse = append(submissionResponse.LogResponse, ctgo.AddChainResponse{
				SCTVersion: mimicSCT.SCTVersion,
				ID:         mimicSCT.LogID.KeyID[:],
				Timestamp:  mimicSCT.Timestamp,
				Extensions: base64.StdEncoding.EncodeToString(mimicSCT.Extensions),
				Signature:  sig,
			})
		}
	}

	// Encode the final SCT list.
	sctListBytes, err := pki.MarshalSCTList(scts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SCT list: %w", err)
	}

	if entryType == ctgo.PrecertLogEntryType {
		// Optionally include the serialized SCT list, to assist CAs in constructing the final TBSCertificate themselves.
		// This is disabled by default; see the response.includeSCTList configuration option.
		if config.Config.Response.IncludeSCTList {
			submissionResponse.SCTListB64 = base64.StdEncoding.EncodeToString(sctListBytes)
		}

		// Optionally generate and return the final TBSCertificate (with SCTs embedded and CT poison removed).
		// WARNING: CAs that blindly sign this value are trusting ctsubmit with their signing key's output.
		// This is disabled by default; see the response.produceFinalTBSCert configuration option.
		if config.Config.Response.ProduceFinalTBSCert {
			tbsCertificate, err := pki.ProduceFinalTBSCertificate(detoxedTBSCert, sctListBytes)
			if err != nil {
				return nil, fmt.Errorf("Failed to generate final TBSCertificate: %v", err)
			}

			// Base64-encode the final TBSCertificate for inclusion in the response.
			submissionResponse.FinalTBSCertB64 = base64.StdEncoding.EncodeToString(tbsCertificate)

			// Evaluate CT policy compliance using ctlint, and include the linter findings in the response.
			submissionResponse.CTLint = runCTLint(tbsCertificate)
		}
	}

	// Omit LogResponse from the response if configured.
	if !config.Config.Response.IncludeLogResponses {
		submissionResponse.LogResponse = nil
	}

	// If requested, include the strategy information in the response.
	if submissionRequest.Verbose {
		submissionResponse.Strategy = strategy
	}

	return submissionResponse, nil
}
