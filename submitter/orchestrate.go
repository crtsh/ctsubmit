package submitter

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/monitor"

	json "github.com/goccy/go-json"
	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"
)

var errQuorumMet = errors.New("quorum met")

func (sr *SubmissionRequest) submit(ctx context.Context, strategy []StrategyMember, sha256IssuerSPKI *[sha256.Size]byte, entryType ctgo.LogEntryType, entryData []byte) ([]ctgo.AddChainResponse, []*ctgo.SignedCertificateTimestamp, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	// Determine the API path for the submission.
	apiPath := ""
	switch entryType {
	case ctgo.X509LogEntryType:
		apiPath = "ct/v1/add-chain"
	case ctgo.PrecertLogEntryType:
		apiPath = "ct/v1/add-pre-chain"
	default:
		return nil, nil, fmt.Errorf("unsupported log entry type: %v", entryType)
	}

	// Marshal the request body once, since it's the same for all logs. Strip the additional fields that ctsubmit recognizes but logs won't recognize.
	requestBody, err := json.Marshal(ctgo.AddChainRequest{Chain: sr.AddChainRequest.Chain})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal submission request: %w", err)
	}

	// Filter out excluded logs from the strategy.
	var eligible []int
	for i := range strategy {
		if strategy[i].Bucket != EXCLUDED {
			eligible = append(eligible, i)
		}
	}
	if len(eligible) == 0 {
		return nil, nil, fmt.Errorf("no eligible logs in strategy")
	}

	start := time.Now()
	submissionCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// On return, annotate any eligible logs that were never contacted.
	defer func() {
		for _, idx := range eligible {
			if strategy[idx].Outcome == "" {
				strategy[idx].Outcome = "Submission not attempted"
			}
		}
	}()

	events := make(chan submissionEvent, len(eligible))
	qs := newQuorumState()

	inFlight := 0
	inFlightIndices := make(map[int]bool)     // strategy indices currently in-flight (not yet slow)
	slowInFlightIndices := make(map[int]bool) // strategy indices in-flight but past try-next threshold
	launchSeq := 0

	// launchEligible launches a goroutine to submit to the log at eligible[eligibleIdx].
	launchEligible := func(eligibleIdx int) {
		strategyIdx := eligible[eligibleIdx]
		inFlight++
		inFlightIndices[strategyIdx] = true
		launchSeq++
		strategy[strategyIdx].BeganAfter = time.Since(start)
		logger.Logger.Debug("Launching submission", zap.Int("launchSeq", launchSeq), zap.Int("strategyIdx", strategyIdx), zap.String("url", strategy[strategyIdx].SubmissionURL), zap.String("operator", strategy[strategyIdx].Operator), zap.Int("inFlight", inFlight))

		go func(idx int) {
			submitToLog(submissionCtx, idx, strategy[idx].SubmissionURL, apiPath, requestBody, sha256IssuerSPKI, entryType, entryData, events)
		}(strategyIdx)
	}

	// Start initial batch: up to sr.SCTs concurrent submissions.
	// Ensure at least one log of each required/preferred type is included in the initial batch.
	initialBatch := sr.SCTs
	if initialBatch > len(eligible) {
		initialBatch = len(eligible)
	}
	ensureLogType := func(logType LogType) {
		if launchSeq >= initialBatch {
			return
		}
		for i, strategyIdx := range eligible {
			if strategy[strategyIdx].BeganAfter != 0 {
				continue
			}
			if strategy[strategyIdx].LogType == logType {
				launchEligible(i)
				return
			}
		}
	}
	if sr.RequireAtLeastOneRFC6962SCT {
		ensureLogType(LOGTYPE_RFC6962)
	}
	if sr.PreferAtLeastOneStaticSCT {
		ensureLogType(LOGTYPE_STATIC)
	}
	for i := 0; i < len(eligible) && launchSeq < initialBatch; i++ {
		if strategy[eligible[i]].BeganAfter != 0 {
			continue
		}
		launchEligible(i)
	}

	// startNextEligible scans all unattempted eligible logs (in strategy order) and starts
	// the first one that would help meet quorum.  Previously skipped logs are reconsidered
	// because an in-flight request that made them redundant may have since failed.
	// If a log-type requirement/preference is unmet and not covered by any in-flight
	// submission, the first eligible log of that type is preferred over strategy order.
	startNextEligible := func() {
		// Check if we need to prioritize a specific log type.
		needRFC6962 := sr.RequireAtLeastOneRFC6962SCT && !qs.hasRFC6962SCT
		needStatic := sr.PreferAtLeastOneStaticSCT && !qs.hasStaticSCT
		if needRFC6962 || needStatic {
			// Check whether any non-slow in-flight submission already covers the needed log type.
			// Slow in-flight submissions are excluded because they triggered try-next precisely
			// because they are unreliable.
			for idx := range inFlightIndices {
				if needRFC6962 && strategy[idx].LogType == LOGTYPE_RFC6962 {
					needRFC6962 = false
				}
				if needStatic && strategy[idx].LogType == LOGTYPE_STATIC {
					needStatic = false
				}
			}
		}
		if needRFC6962 || needStatic {
			for i, strategyIdx := range eligible {
				if strategy[strategyIdx].BeganAfter != 0 {
					continue
				}
				sm := strategy[strategyIdx]
				if needRFC6962 && sm.LogType == LOGTYPE_RFC6962 || needStatic && sm.LogType == LOGTYPE_STATIC {
					if qs.wouldHelp(sr, sm, strategy, inFlightIndices) {
						logger.Logger.Debug("Next eligible helps quorum (log type preference)", zap.Int("strategyIdx", strategyIdx), zap.String("url", sm.SubmissionURL), zap.String("operator", sm.Operator), zap.Int("logType", int(sm.LogType)))
						launchEligible(i)
						return
					}
				}
			}
		}
		for i, strategyIdx := range eligible {
			if strategy[strategyIdx].BeganAfter != 0 {
				continue
			}
			sm := strategy[strategyIdx]
			if qs.wouldHelp(sr, sm, strategy, inFlightIndices) {
				logger.Logger.Debug("Next eligible helps quorum", zap.Int("strategyIdx", strategyIdx), zap.String("url", sm.SubmissionURL), zap.String("operator", sm.Operator))
				launchEligible(i)
				return
			}
		}
	}

	// Process events until quorum is met or all attempts are exhausted.
	for inFlight > 0 {
		var event submissionEvent
		select {
		case event = <-events:
		case <-ctx.Done():
			cancel(ctx.Err())
			for inFlight > 0 {
				ev := <-events
				if ev.eventType == eventSuccess || ev.eventType == eventFailure {
					inFlight--
					strategy[ev.strategyIdx].TimeTaken = ev.timeTaken
					if strategy[ev.strategyIdx].Outcome == "" {
						strategy[ev.strategyIdx].Outcome = ev.outcome
					}
				}
			}
			return nil, nil, ctx.Err()
		}

		switch event.eventType {
		case eventSuccess:
			inFlight--
			delete(inFlightIndices, event.strategyIdx)
			delete(slowInFlightIndices, event.strategyIdx)
			strategy[event.strategyIdx].TimeTaken = event.timeTaken
			if qs.helpsQuorum(sr, strategy[event.strategyIdx]) {
				strategy[event.strategyIdx].Outcome = event.outcome
				qs.addSuccess(strategy, event.strategyIdx, event.response, event.sct)
			} else {
				strategy[event.strategyIdx].Outcome = "Submission successful, but doesn't help quorum"
			}
			logger.Logger.Debug("Submission success", zap.Int("strategyIdx", event.strategyIdx), zap.String("url", strategy[event.strategyIdx].SubmissionURL), zap.String("operator", strategy[event.strategyIdx].Operator), zap.Int("scts", len(qs.responses)), zap.Int("sctsNeeded", sr.SCTs), zap.Int("operators", len(qs.operators)), zap.Int("operatorsNeeded", sr.Operators), zap.Int("inFlight", inFlight))

			if qs.isQuorumMet(sr) {
				logger.Logger.Debug("Quorum met; cancelling remaining in-flight submissions", zap.Int("inFlight", inFlight))
				for _, indices := range []map[int]bool{inFlightIndices, slowInFlightIndices} {
					for idx := range indices {
						strategy[idx].Outcome = "Submission cancelled (quorum met)"
					}
				}
				cancel(errQuorumMet)
				// Drain events from cancelled goroutines to capture their timeTaken.
				for inFlight > 0 {
					ev := <-events
					if ev.eventType == eventSuccess || ev.eventType == eventFailure {
						inFlight--
						strategy[ev.strategyIdx].TimeTaken = ev.timeTaken
					}
				}
				qs.trimToQuorum(sr, strategy)
				return qs.responses, qs.scts, nil
			}
			if inFlight == 0 {
				startNextEligible()
			}

		case eventFailure:
			inFlight--
			delete(inFlightIndices, event.strategyIdx)
			delete(slowInFlightIndices, event.strategyIdx)
			strategy[event.strategyIdx].Outcome = event.outcome
			strategy[event.strategyIdx].TimeTaken = event.timeTaken
			logger.Logger.Warn("Submission failure", zap.Int("strategyIdx", event.strategyIdx), zap.String("url", strategy[event.strategyIdx].SubmissionURL), zap.String("operator", strategy[event.strategyIdx].Operator), zap.Int("inFlight", inFlight))
			if inFlight == 0 {
				startNextEligible()
			}

		case eventTryNext:
			// An in-flight submission has exceeded the try-next threshold; move it to the
			// slow set so wouldHelp no longer counts it optimistically, then start the next
			// eligible log (the slow submission continues and might still succeed).
			delete(inFlightIndices, event.strategyIdx)
			slowInFlightIndices[event.strategyIdx] = true
			logger.Logger.Warn("Try-next threshold exceeded; launching additional candidate", zap.Int("strategyIdx", event.strategyIdx), zap.String("url", strategy[event.strategyIdx].SubmissionURL), zap.String("operator", strategy[event.strategyIdx].Operator))
			startNextEligible()

		case eventSlow:
			monitor.RecordSlowResponse(strategy[event.strategyIdx].SubmissionURL)
			logger.Logger.Warn("Slow response threshold exceeded", zap.Int("strategyIdx", event.strategyIdx), zap.String("url", strategy[event.strategyIdx].SubmissionURL), zap.String("operator", strategy[event.strategyIdx].Operator))
		}
	}

	// All logs attempted; check if quorum was met despite not being detected in the loop
	// (shouldn't happen, but be safe).
	if qs.isQuorumMet(sr) {
		qs.trimToQuorum(sr, strategy)
		return qs.responses, qs.scts, nil
	}

	return nil, nil, fmt.Errorf("quorum not achieved: %s", qs.quorumFailureReason(sr))
}
