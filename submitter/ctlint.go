package submitter

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/crtsh/ctsubmit/pki"

	"github.com/crtsh/ctlint"
)

// testLogFindingSubstrings identifies ctlint findings that arise solely because
// an SCT's log is absent from (or not approved in) the production CT log lists
// bundled with ctlint. These are expected when submitting to test logs, so they
// are suppressed when the request's testLogs setting is enabled.
var testLogFindingSubstrings = []string{
	"logs currently approved by the",                       // Chrome/Apple/Mozilla/Mark: no SCTs from currently approved logs.
	"fewer approved SCTs than required by the",             // Not enough SCTs from approved logs.
	"SCT list satisfies the",                               // Reliance on a not-yet-usable Qualified/Admissible log.
	"fewer log operators than required by the",             // Not enough distinct approved log operators.
	"fewer SCTs from RFC6962-compliant logs than required", // No SCT from an approved RFC6962-compliant log.
	"Certificate expires outside log's temporal interval",  // Temporal shard check against production logs.
	"SCT is from an unknown log",                           // Test log's key is absent from ctlint's verifier map.
}

// isTestLogFinding reports whether a (prefix-stripped) ctlint finding is one that
// is expected when submitting to test logs rather than production CT logs.
func isTestLogFinding(finding string) bool {
	for _, s := range testLogFindingSubstrings {
		if strings.Contains(finding, s) {
			return true
		}
	}
	return false
}

func runCTLint(tbsCertificate []byte, sha256IssuerSPKI *[sha256.Size]byte, testMode bool) []CTLintResult {
	var lres []CTLintResult

	dummyCert, err := pki.MakeDummyCertificate(tbsCertificate)
	if err != nil {
		lres = append(lres, CTLintResult{
			Finding:  fmt.Sprintf("Failed to create dummy certificate: %v", err),
			Severity: "fatal",
		})
	} else {
		results := ctlint.CheckCertificate(dummyCert, sha256IssuerSPKI)
		for _, result := range results {
			lresult := CTLintResult{
				Finding: result[3:],
			}
			switch result[0:3] {
			case "I: ":
				lresult.Severity = "info"
			case "N: ":
				lresult.Severity = "notice"
			case "W: ":
				lresult.Severity = "warning"
			case "E: ":
				lresult.Severity = "error"
			case "B: ":
				lresult.Severity = "bug"
			case "F: ":
				lresult.Severity = "fatal"
			default:
				continue
			}
			// In test mode, suppress findings that only occur because the SCTs come
			// from test logs that are absent from the production CT log lists.
			if testMode && isTestLogFinding(lresult.Finding) {
				continue
			}
			lres = append(lres, lresult)
		}
	}

	return lres
}
