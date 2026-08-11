package submitter

import (
	"cmp"
	"crypto/rand"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/monitor"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
)

type StrategyMember struct {
	SubmissionURL      string        `json:"submissionURL,omitempty"`
	MonitoringURL      string        `json:"monitoringURL,omitempty"`
	Operator           string        `json:"operator,omitempty"`
	LogName            string        `json:"logName,omitempty"`
	LogType            LogType       `json:"logType"`
	MMD                int32         `json:"mmd,omitempty"`
	Bucket             Bucket        `json:"bucket"`
	DispreferredDetail string        `json:"dispreferredDetail,omitempty"`
	RandomWeight       int           `json:"randomWeight,omitempty"`
	Outcome            string        `json:"outcome,omitempty"`
	BeganAfter         time.Duration `json:"beganAfter,omitempty"`
	TimeTaken          time.Duration `json:"timeTaken,omitempty"`
}

// compileRegexes compiles URL match patterns from config. It panics on an
// invalid pattern (via regexp.MustCompile), preserving the startup fail-fast
// behaviour now that compilation happens in New rather than an init function.
func compileRegexes(patterns []string) []*regexp.Regexp {
	var regexes []*regexp.Regexp
	for _, pattern := range patterns {
		regexes = append(regexes, regexp.MustCompile(pattern))
	}
	return regexes
}

func (s *Submitter) devizeSubmissionStrategy(compatibleLogList *loglist3.LogList, entryType ctgo.LogEntryType) []StrategyMember {
	var strategy []StrategyMember

	// Populate strategy list with the compatible logs.
	for _, operator := range compatibleLogList.Operators {
		sm := StrategyMember{Operator: operator.Name, Bucket: NEUTRAL}

		// Check if this operator is excluded by config.
		if slices.Contains(s.cfg.Strategy.Excluded.Operators, operator.Name) {
			sm.Bucket = EXCLUDED
			sm.Outcome = "Operator excluded by config"
		}

		// Append RFC6962 logs for this operator.
		for _, log := range operator.Logs {
			submissionURL, _ := url.JoinPath(log.URL, "/")
			sm.SubmissionURL = submissionURL
			sm.MonitoringURL = submissionURL
			sm.LogName = log.Description
			sm.LogType = LOGTYPE_RFC6962
			sm.MMD = log.MMD
			strategy = append(strategy, sm)
		}

		// Append Static logs for this operator.
		for _, tiledLog := range operator.TiledLogs {
			submissionURL, _ := url.JoinPath(tiledLog.SubmissionURL, "/")
			monitoringURL, _ := url.JoinPath(tiledLog.MonitoringURL, "/")
			sm.SubmissionURL = submissionURL
			sm.MonitoringURL = monitoringURL
			sm.LogName = tiledLog.Description
			sm.LogType = LOGTYPE_STATIC
			sm.MMD = tiledLog.MMD
			strategy = append(strategy, sm)
		}
	}

	for i := 0; i < len(strategy); i++ {
		// Apply log exclusion config.
		strategy[i].applyLogExclusionConfig(strategy[i].SubmissionURL, s.excludedURLRegexes)

		// Disprefer logs with STH ages that exceed the MMD.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIfMMDBlown()
		}

		// Disprefer logs with endpoint uptimes below configurable thresholds.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIfLowUptime(entryType)
		}

		// Disprefer logs from which we've received a bad response recently.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIfBadResponseBackoff()
		}

		// Disprefer logs for which a request recently timed out.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIfTimeoutBackoff()
		}

		// Disprefer logs from which we've received a 5xx response recently (as defined by Retry-After if received, or else by the configurable back-off period).
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIf5xxBackoff()
		}

		// Disprefer logs from which we've received a 4xx response recently (as defined by Retry-After if received, or else by the configurable back-off period).
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIf4xxBackoff()
		}

		// Disprefer logs for which we've recently observed slow responses.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].dispreferIfSlowResponseBackoff()
		}

		// Apply log preference config.
		if strategy[i].Bucket == NEUTRAL {
			strategy[i].applyLogPreferenceConfig(strategy[i].SubmissionURL, s.preferredURLRegexes)
		}

		// Generate a random weight for each non-excluded log, for use in randomizing the order of logs within buckets.
		// This is to ensure that if we have more compatible logs than we need for a given submission request, we don't always submit to the same ones at the front of the list.
		// Note that we do this before sorting, so that logs within each bucket are sorted at random.
		if strategy[i].Bucket != EXCLUDED {
			n, _ := rand.Int(rand.Reader, big.NewInt(1000))
			strategy[i].RandomWeight = int(n.Int64())
		}
	}

	// Sort strategy members according to their bucket, then random weight.
	slices.SortFunc(strategy, sortStrategyMembers)

	return strategy
}

func (sm *StrategyMember) applyLogExclusionConfig(submissionURL string, regexes []*regexp.Regexp) {
	for _, re := range regexes {
		if re.MatchString(submissionURL) {
			sm.Bucket = EXCLUDED
			sm.Outcome = "Log excluded by config"
			return
		}
	}
}

func (sm *StrategyMember) dispreferIfMMDBlown() {
	sd, ok := monitor.GetSTHData(sm.MonitoringURL)
	if !ok {
		sm.Bucket = EXCLUDED
		sm.Outcome = "No STH timestamp available"
		return
	}

	if sd.Timestamp != nil {
		sthAge := time.Since(*sd.Timestamp)
		if sthAge > (time.Duration(sm.MMD) * time.Second) {
			sm.Bucket = DISPREFERRED_MMDBLOWN
			sm.DispreferredDetail = fmt.Sprintf("STH age exceeds MMD (%v > %v)", sthAge, sm.MMD)
		}
	}
}

func (sm *StrategyMember) dispreferIfLowUptime(entryType ctgo.LogEntryType) {
	var endpointUptime float64
	var ok bool
	if entryType == ctgo.PrecertLogEntryType {
		endpointUptime, ok = monitor.GetEndpointUptime24h(sm.SubmissionURL, "add-pre-chain")
	} else {
		endpointUptime, ok = monitor.GetEndpointUptime24h(sm.SubmissionURL, "add-chain")
	}

	if ok && endpointUptime < config.Config.Strategy.UptimeThreshold.SubmitEndpoint24h {
		sm.Bucket = DISPREFERRED_LOWUPTIME
		sm.DispreferredDetail = fmt.Sprintf("Submission endpoint 24h uptime below threshold (%.4f%% < %.4f%%)", endpointUptime, config.Config.Strategy.UptimeThreshold.SubmitEndpoint24h)
	}

	endpointUptime, ok = monitor.GetEndpointUptime90d(sm.SubmissionURL, "LOWEST")
	if ok && endpointUptime < config.Config.Strategy.UptimeThreshold.LowestEndpoint90d {
		sm.Bucket = DISPREFERRED_LOWUPTIME
		sm.DispreferredDetail = fmt.Sprintf("Lowest endpoint 90d uptime below threshold (%.4f%% < %.4f%%)", endpointUptime, config.Config.Strategy.UptimeThreshold.LowestEndpoint90d)
	}
}

func (sm *StrategyMember) dispreferIfBadResponseBackoff() {
	backoffDuration, reason := monitor.GetBadResponseBackoff(sm.SubmissionURL)
	if backoffDuration > 0 {
		sm.Bucket = DISPREFERRED_RECENTBADRESPONSE
		sm.DispreferredDetail = reason
	}
}

func (sm *StrategyMember) dispreferIfTimeoutBackoff() {
	backoffDuration, reason := monitor.GetTimeoutBackoff(sm.SubmissionURL)
	if backoffDuration > 0 {
		sm.Bucket = DISPREFERRED_RECENTTIMEOUT
		sm.DispreferredDetail = reason
	}
}

func (sm *StrategyMember) dispreferIf5xxBackoff() {
	backoffDuration, reason, _ := monitor.Get5xxBackoff(sm.SubmissionURL)
	if backoffDuration > 0 {
		sm.Bucket = DISPREFERRED_RECENT5XX
		sm.DispreferredDetail = reason
	}
}

func (sm *StrategyMember) dispreferIf4xxBackoff() {
	backoffDuration, reason, _ := monitor.Get4xxBackoff(sm.SubmissionURL)
	if backoffDuration > 0 {
		sm.Bucket = DISPREFERRED_RECENT4XX
		sm.DispreferredDetail = reason
	}
}

func (sm *StrategyMember) dispreferIfSlowResponseBackoff() {
	backoffDuration, reason := monitor.GetSlowResponseBackoff(sm.SubmissionURL)
	if backoffDuration > 0 {
		sm.Bucket = DISPREFERRED_SLOWRESPONSES
		sm.DispreferredDetail = reason
	}
}

func (sm *StrategyMember) applyLogPreferenceConfig(submissionURL string, regexes []*regexp.Regexp) {
	if sm.Bucket != EXCLUDED {
		for _, re := range regexes {
			if re.MatchString(submissionURL) {
				sm.Bucket = PREFERRED_BYCONFIG
				return
			}
		}
	}
}

func sortStrategyMembers(sm1, sm2 StrategyMember) int {
	if result := cmp.Compare(sm1.Bucket, sm2.Bucket); result != 0 {
		return -result
	}

	return cmp.Compare(sm1.RandomWeight, sm2.RandomWeight)
}
