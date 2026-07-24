package submitter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"
	"github.com/crtsh/ctsubmit/utils"

	"github.com/crtsh/ctloglists"
	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"
)

var submissionHTTPClient *http.Client

func init() {
	submissionHTTPClient = &http.Client{Timeout: config.Config.Strategy.Submission.HTTPTimeout}
}

// submitToLog performs the HTTP submission to a single log and sends events on the channel.
// It sends eventTryNext if the try-next threshold is exceeded before the HTTP response,
// and eventSlow if the slow response threshold is exceeded (for metrics).
// It then sends eventSuccess or eventFailure when the HTTP response completes.
func submitToLog(ctx context.Context, strategyIdx int, submissionURL string, apiPath string, requestBody []byte, sha256IssuerSPKI *[sha256.Size]byte, entryType ctgo.LogEntryType, entryData []byte, events chan<- submissionEvent) {
	endpointURL, err := url.JoinPath(submissionURL, apiPath)
	if err != nil {
		logger.Logger.Error("Failed to construct submission URL", zap.String("submissionURL", submissionURL), zap.Error(err))
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: could not construct submission URL: %v", err)}
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewReader(requestBody))
	if err != nil {
		logger.Logger.Error("Failed to create HTTP request", zap.String("url", endpointURL), zap.Error(err))
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: could not create HTTP request: %v", err)}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "github.com/crtsh/ct_submit")
	req_body_sha256 := sha256.Sum256(requestBody)
	req.Header.Set("Idempotency-Key", hex.EncodeToString(req_body_sha256[:]))

	// Start one-shot timers for try-next and slow response detection.
	tryNextTimer := time.NewTimer(config.Config.Strategy.Submission.TryNextResponseThreshold)
	defer tryNextTimer.Stop()
	slowTimer := time.NewTimer(config.Config.Strategy.Submission.SlowResponseThreshold)
	defer slowTimer.Stop()

	// Run the HTTP request in a separate goroutine so we can race it against the timers.
	type httpResult struct {
		resp *http.Response
		err  error
	}
	httpCh := make(chan httpResult, 1)
	httpStart := time.Now()
	go func() {
		resp, err := submissionHTTPClient.Do(req)
		httpCh <- httpResult{resp: resp, err: err}
	}()

	tryNextSent := false
	slowSent := false
	for {
		select {
		case <-tryNextTimer.C:
			if !tryNextSent {
				tryNextSent = true
				events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventTryNext}
			}

		case <-slowTimer.C:
			if !slowSent {
				slowSent = true
				events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventSlow}
			}

		case result := <-httpCh:
			timeTaken := time.Since(httpStart)
			if ctx.Err() != nil {
				// Context was cancelled around the same time the HTTP response arrived.
				if result.resp != nil {
					result.resp.Body.Close()
				}
				events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: cancelledSubmissionOutcome(ctx), timeTaken: timeTaken}
				monitor.RecordSubmissionOutcome(submissionURL, "cancelled")
				return
			}
			processHTTPResponse(strategyIdx, submissionURL, result.resp, result.err, sha256IssuerSPKI, entryType, entryData, timeTaken, events)
			return

		case <-ctx.Done():
			// Context cancelled. Wait briefly for any in-flight HTTP response,
			// but don't block indefinitely.
			select {
			case result := <-httpCh:
				if result.resp != nil {
					result.resp.Body.Close()
				}
			case <-time.After(100 * time.Millisecond):
			}
			events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: cancelledSubmissionOutcome(ctx), timeTaken: time.Since(httpStart)}
			monitor.RecordSubmissionOutcome(submissionURL, "cancelled")
			return
		}
	}
}

func cancelledSubmissionOutcome(ctx context.Context) string {
	switch cause := context.Cause(ctx); {
	case cause == errQuorumMet:
		return "Cancelled: quorum met"
	case cause == context.DeadlineExceeded:
		return "Cancelled: request deadline exceeded"
	case cause == context.Canceled:
		return "Cancelled: request cancelled"
	case cause != nil:
		return fmt.Sprintf("Cancelled: %v", cause)
	default:
		return "Cancelled"
	}
}

func processHTTPResponse(strategyIdx int, submissionURL string, resp *http.Response, err error, sha256IssuerSPKI *[sha256.Size]byte, entryType ctgo.LogEntryType, entryData []byte, timeTaken time.Duration, events chan<- submissionEvent) {
	monitor.RecordSubmissionResponseTime(submissionURL, timeTaken)

	if err != nil {
		if utils.IsTimeoutError(err) {
			monitor.RecordTimeout(submissionURL, err)
			events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: "Failed: timeout", timeTaken: timeTaken}
			monitor.RecordSubmissionOutcome(submissionURL, "timeout")
		} else {
			monitor.RecordBadResponse(submissionURL, err)
			events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: HTTP error: %v", err), timeTaken: timeTaken}
			monitor.RecordSubmissionOutcome(submissionURL, "http_error")
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		monitor.RecordBadResponse(submissionURL, err)
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: could not read response body: %v", err), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, "bad_response")
		return
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			monitor.Record5xxResponse(submissionURL, resp)
		} else if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			monitor.Record4xxResponse(submissionURL, resp)
		} else {
			monitor.RecordBadResponse(submissionURL, fmt.Errorf("Unexpected HTTP status: %d", resp.StatusCode))
		}

		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: HTTP %d", resp.StatusCode), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, fmt.Sprintf("%dxx", resp.StatusCode/100))
		return
	}

	// Unmarshal the JSON response.
	var addChainResponse ctgo.AddChainResponse
	if err := json.Unmarshal(body, &addChainResponse); err != nil {
		monitor.RecordBadResponse(submissionURL, err)
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: invalid JSON response: %v", err), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, "bad_response")
		return
	}

	// Encode the SCT.
	sct, err := addChainResponse.ToSignedCertificateTimestamp()
	if err != nil {
		monitor.RecordBadResponse(submissionURL, err)
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: could not decode SCT: %v", err), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, "bad_response")
		return
	}

	// Reject the SCT if its timestamp is in the future.  Allow 1 second of tolerance for clock skew.
	if time.UnixMilli(int64(sct.Timestamp)).After(time.Now().Add(time.Second)) {
		monitor.RecordBadResponse(submissionURL, fmt.Errorf("SCT timestamp is %s in the future", time.Until(time.UnixMilli(int64(sct.Timestamp))).String()))
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: SCT timestamp in the future (%d)", sct.Timestamp), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, "bad_response")
		return
	}

	// Verify the SCT's signature.
	err = verifySCTSignature(sct, sha256IssuerSPKI, entryType, entryData)
	if err != nil {
		monitor.RecordBadResponse(submissionURL, err)
		events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventFailure, outcome: fmt.Sprintf("Failed: SCT signature verification failed: %v", err), timeTaken: timeTaken}
		monitor.RecordSubmissionOutcome(submissionURL, "bad_response")
		return
	}

	logger.Logger.Debug("Accepted SCT", zap.Int("strategyIdx", strategyIdx), zap.String("submissionURL", submissionURL), zap.String("logID", hex.EncodeToString(sct.LogID.KeyID[:])), zap.Uint64("timestamp", sct.Timestamp))
	events <- submissionEvent{strategyIdx: strategyIdx, eventType: eventSuccess, response: addChainResponse, sct: sct, outcome: "Submission successful", timeTaken: timeTaken}
	monitor.RecordSubmissionOutcome(submissionURL, "success")
}

func verifySCTSignature(sct *ctgo.SignedCertificateTimestamp, sha256IssuerSPKI *[sha256.Size]byte, entryType ctgo.LogEntryType, entryData []byte) error {
	sv := ctloglists.LogSignatureVerifierMap[([sha256.Size]byte)(sct.LogID.KeyID)]
	if sv == nil {
		return fmt.Errorf("SCT is from an unknown log")
	}

	leaf := &ctgo.MerkleTreeLeaf{
		Version:  ctgo.V1,
		LeafType: ctgo.TimestampedEntryLeafType,
		TimestampedEntry: &ctgo.TimestampedEntry{
			EntryType: entryType,
			Timestamp: sct.Timestamp,
		},
	}
	if entryType == ctgo.PrecertLogEntryType {
		leaf.TimestampedEntry.PrecertEntry = &ctgo.PreCert{
			IssuerKeyHash:  *sha256IssuerSPKI,
			TBSCertificate: entryData,
		}
	} else {
		leaf.TimestampedEntry.X509Entry = &ctgo.ASN1Cert{
			Data: entryData,
		}
	}

	// Verify the SCT's signature against the constructed log entry.
	return sv.VerifySCTSignature(*sct, ctgo.LogEntry{Leaf: *leaf})
}
