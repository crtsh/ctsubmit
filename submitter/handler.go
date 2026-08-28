package submitter

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/pki"

	"github.com/crtsh/ccadb_data"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/asn1"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
)

// Handle processes a submission request. When the request asked for the
// strategy, a non-nil response carrying it is returned alongside any error
// raised from the strategy onwards.
func (s *Submitter) Handle(ctx context.Context, apiEndpoint endpoint.Endpoint, submissionRequest *SubmissionRequest) (*SubmissionResponse, error) {
	// Check "chain" parameter is present and contains at least one certificate.
	if len(submissionRequest.Chain) == 0 {
		return nil, fmt.Errorf("missing or empty 'chain' parameter")
	}

	// Parse the first certificate in the chain.
	cert, err := x509.ParseCertificate(submissionRequest.Chain[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse first certificate: %v", err)
	}

	// Ensure appropriate input for add-chain vs add-pre-chain.
	var entryType ctgo.LogEntryType
	var entryData []byte
	var detoxedTBSCert *pki.TBSCertificate
	if cert.IsPrecertificate() {
		if apiEndpoint == endpoint.ENDPOINT_ADDCHAIN {
			return nil, fmt.Errorf("precertificate submitted to add-chain endpoint")
		}

		entryType = ctgo.PrecertLogEntryType

		// Remove the CT Poison extension from the precertificate to produce the "detoxed" TBSCertificate.
		if detoxedTBSCert, err = pki.DetoxTBSCertificateFromPrecertificate(cert.Raw); err != nil {
			return nil, fmt.Errorf("failed to detox precertificate: %v", err)
		}

		// Re-marshal the detoxed TBSCertificate.
		entryData, err = asn1.Marshal(*detoxedTBSCert)
		if err != nil {
			return nil, fmt.Errorf("failed to re-marshal TBSCertificate: %v", err)
		}

	} else {
		if apiEndpoint == endpoint.ENDPOINT_ADDPRECHAIN {
			return nil, fmt.Errorf("certificate submitted to add-pre-chain endpoint")
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
	strategy := s.devizeSubmissionStrategy(compatibleLogList, entryType)

	// Build the response up-front, so that a requested strategy is still returned if submission subsequently fails.
	submissionResponse := &SubmissionResponse{}
	if submissionRequest.Verbose {
		submissionResponse.Strategy = strategy
	}

	// Compute or lookup the issuer certificate's SPKI SHA-256 hash.
	var sha256IssuerSPKI *[sha256.Size]byte
	if len(submissionRequest.Chain) > 1 {
		issuer, err := x509.ParseCertificate(submissionRequest.Chain[1])
		if err != nil {
			return submissionResponse, fmt.Errorf("failed to parse issuer certificate: %v", err)
		}
		hash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		sha256IssuerSPKI = &hash
	} else {
		if hash, found := ccadb_data.GetIssuerSPKISHA256ByKeyIdentifier(base64.StdEncoding.EncodeToString(cert.AuthorityKeyId)); found {
			sha256IssuerSPKI = &hash
		}
	}

	// Submit to the logs.
	var scts []*ctgo.SignedCertificateTimestamp
	submissionResponse.LogResponse, scts, err = s.submit(ctx, submissionRequest, strategy, sha256IssuerSPKI, entryType, entryData)
	if err != nil {
		return submissionResponse, fmt.Errorf("submission failed: %v", err)
	}

	// If requested, generate mimic SCTs.
	if submissionRequest.Mimics && sha256IssuerSPKI != nil {
		mimicSCTs, err := pki.GenerateMimicSCTs(entryData, *sha256IssuerSPKI)
		if err != nil {
			return submissionResponse, fmt.Errorf("failed to generate mimic SCTs: %v", err)
		}

		// Append the mimic SCTs to the SCT list to be embedded in the final TBSCertificate.
		scts = append(scts, mimicSCTs...)

		// Include the mimic SCTs in the response's LogResponse.
		for _, mimicSCT := range mimicSCTs {
			sig, err := tls.Marshal(mimicSCT.Signature)
			if err != nil {
				return submissionResponse, fmt.Errorf("failed to marshal mimic SCT signature: %v", err)
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
		return submissionResponse, fmt.Errorf("failed to marshal SCT list: %w", err)
	}

	if entryType == ctgo.PrecertLogEntryType {
		// Optionally include the serialized SCT list, to assist CAs in constructing the final TBSCertificate themselves.
		// This is disabled by default; see the response.includeSCTList configuration option.
		if s.cfg.Response.IncludeSCTList {
			submissionResponse.SCTListB64 = base64.StdEncoding.EncodeToString(sctListBytes)
		}

		// Optionally generate and return the final TBSCertificate (with SCTs embedded and CT poison removed).
		// WARNING: CAs that blindly sign this value are trusting ctsubmit with their signing key's output.
		// This is disabled by default; see the response.produceFinalTBSCert configuration option.
		if s.cfg.Response.ProduceFinalTBSCert {
			tbsCertificate, err := pki.ProduceFinalTBSCertificate(detoxedTBSCert, sctListBytes)
			if err != nil {
				return submissionResponse, fmt.Errorf("failed to generate final TBSCertificate: %v", err)
			}

			// Base64-encode the final TBSCertificate for inclusion in the response.
			submissionResponse.FinalTBSCertB64 = base64.StdEncoding.EncodeToString(tbsCertificate)

			// Evaluate CT policy compliance using ctlint, and include the linter findings in the response.
			// In test-log mode, suppress the findings that only occur because test logs are absent from the production CT log lists.
			submissionResponse.CTLint = runCTLint(tbsCertificate, sha256IssuerSPKI, submissionRequest.TestLogs)
		}
	}

	// Omit LogResponse from the response if configured.
	if !s.cfg.Response.IncludeLogResponses {
		submissionResponse.LogResponse = nil
	}

	return submissionResponse, nil
}
