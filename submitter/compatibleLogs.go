package submitter

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/crtsh/ctsubmit/pki"

	"github.com/google/certificate-transparency-go/logid"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

var LogID_Daedalus = [sha256.Size]byte{0x1d, 0x02, 0x4b, 0x8e, 0xb1, 0x49, 0x8b, 0x34, 0x4d, 0xfd, 0x87, 0xea, 0x3e, 0xfc, 0x09, 0x96, 0xf7, 0x50, 0x6f, 0x23, 0x5d, 0x1d, 0x49, 0x70, 0x61, 0xa4, 0x77, 0x3c, 0x43, 0x9c, 0x25, 0xfb}

func determineCompatibleLogs(cert *x509.Certificate, submissionRequest *SubmissionRequest, logList *loglist3.LogList) (*loglist3.LogList, error) {
	// When CT policy compliance is required (without test logs), ensure the certificate is unexpired.
	if submissionRequest.PolicyCompliant && !submissionRequest.TestLogs && time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate is expired, but policy compliance is required")
	}

	// Filter out logs that are not temporally compatible with the certificate.
	temporallyCompatibleLogList := logList.TemporallyCompatible(cert)

	// Filter out logs for which the chain of CA certificates cannot be validated to an accepted root.
	finalLogList := &loglist3.LogList{}
	totalLogs := 0
	for _, operator := range temporallyCompatibleLogList.Operators {
		op := *operator
		op.Logs = []*loglist3.Log{}
		for _, log := range operator.Logs {
			logID, err := logid.FromBytes(log.LogID)
			if err != nil {
				return nil, fmt.Errorf("failed to parse log ID: %v", err)
			}

			// Treat Daedalus as a special case.  It only accepts expired certificates.
			if logID == LogID_Daedalus && time.Now().Before(cert.NotAfter) {
				continue
			}

			// When CT policy compliance is required (without test logs), we may only use SCTs from logs that are currently Usable.
			if submissionRequest.PolicyCompliant && !submissionRequest.TestLogs {
				if log.State == nil || log.State.Usable == nil || log.State.Usable.Timestamp.After(time.Now()) {
					continue
				} else if log.State.ReadOnly != nil || log.State.Retired != nil || log.State.Rejected != nil {
					continue
				}
			}
			if pki.ValidateChain(logID, submissionRequest.Chain, log.TemporalInterval) {
				op.Logs = append(op.Logs, log)
				totalLogs++
			}
		}
		op.TiledLogs = []*loglist3.TiledLog{}
		for _, tiledLog := range operator.TiledLogs {
			logID, err := logid.FromBytes(tiledLog.LogID)
			if err != nil {
				return nil, fmt.Errorf("failed to parse log ID: %v", err)
			}
			// When CT policy compliance is required (without test logs), we may only use SCTs from logs that are currently Usable.
			if submissionRequest.PolicyCompliant && !submissionRequest.TestLogs {
				if tiledLog.State == nil || tiledLog.State.Usable == nil || tiledLog.State.Usable.Timestamp.After(time.Now()) {
					continue
				} else if tiledLog.State.ReadOnly != nil || tiledLog.State.Retired != nil || tiledLog.State.Rejected != nil {
					continue
				}
			}
			if pki.ValidateChain(logID, submissionRequest.Chain, tiledLog.TemporalInterval) {
				op.TiledLogs = append(op.TiledLogs, tiledLog)
				totalLogs++
			}
		}
		if len(op.Logs) > 0 || len(op.TiledLogs) > 0 {
			finalLogList.Operators = append(finalLogList.Operators, &op)
		}
	}

	// Check we have enough compatible logs to meet the submission request.
	if len(finalLogList.Operators) < submissionRequest.Operators {
		return nil, fmt.Errorf("not enough compatible logs found (required: %d operators, found: %d operators)", submissionRequest.Operators, len(finalLogList.Operators))
	} else if totalLogs < submissionRequest.SCTs {
		return nil, fmt.Errorf("not enough compatible logs found (required: %d SCTs, found: %d SCTs)", submissionRequest.SCTs, totalLogs)
	}

	return finalLogList, nil
}
