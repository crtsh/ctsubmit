package submitter

import (
	"time"

	"github.com/crtsh/ctsubmit/loglists"

	"github.com/crtsh/ctlint"
	"github.com/crtsh/ctloglists"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

type SubmissionRequest struct {
	ctgo.AddChainRequest
	DiscoverChain               bool `json:"discoverChain,omitempty"`
	PolicyCompliant             bool `json:"policyCompliant,omitempty"`
	Mimics                      bool `json:"mimics,omitempty"`
	TestLogs                    bool `json:"testLogs,omitempty"`
	Operators                   int  `json:"operators,omitempty"`
	SCTs                        int  `json:"scts,omitempty"`
	RequireAtLeastOneRFC6962SCT bool `json:"requireAtLeastOneRFC6962SCT,omitempty"`
	PreferAtLeastOneStaticSCT   bool `json:"preferAtLeastOneStaticSCT,omitempty"`
	Verbose                     bool `json:"verbose,omitempty"`
}

func NewSubmissionRequest() *SubmissionRequest {
	return &SubmissionRequest{
		PolicyCompliant: true,
		Operators:       1,
		SCTs:            1,
	}
}

func (sr *SubmissionRequest) determineSubmissionRequirements(cert *x509.Certificate) *loglist3.LogList {
	// Check if this is a Mark Certificate.
	isMarkCertificate := false
	for _, unknownEKU := range cert.UnknownExtKeyUsage {
		if unknownEKU.Equal(ctlint.OIDEKUBrandIndicatorforMessageIdentification) {
			isMarkCertificate = true
			break
		}
	}

	// Determine which base log list to use for this submission request.
	var logList *loglist3.LogList
	if sr.TestLogs {
		logList = loglists.TestTLSLogs
	} else if sr.PolicyCompliant {
		if isMarkCertificate {
			logList = loglists.UsableBIMILogs
		} else {
			logList = loglists.UsableTLSLogs
		}
	} else {
		logList = ctloglists.CrtshV3Active
	}

	// When required, enforce TLS CT policy requirements for SCT/operator diversity.
	if sr.PolicyCompliant && !isMarkCertificate {
		sr.PreferAtLeastOneStaticSCT = true // Requested by Mozilla (see https://github.com/letsencrypt/boulder/pull/8676).

		if sr.Operators < 2 {
			sr.Operators = 2
		}

		scts := 2
		if cert.NotAfter.Sub(cert.NotBefore) > 180*24*time.Hour {
			scts++
		}
		if sr.SCTs < scts {
			sr.SCTs = scts
		}
	}

	// Enforce a bare minimum of 1 SCT and 1 operator.
	if sr.Operators < 1 {
		sr.Operators = 1
	}
	if sr.SCTs < 1 {
		sr.SCTs = 1
	}

	// Ensure the number of SCTs requested is at least enough to satisfy the operator diversity requirement.
	if sr.SCTs < sr.Operators {
		sr.SCTs = sr.Operators
	}

	return logList
}
