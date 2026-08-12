package submitter

import (
	"errors"
	"net/http"
	"regexp"
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/loglists"
	"github.com/crtsh/ctsubmit/monitor"

	ctgo "github.com/google/certificate-transparency-go"

	"go.uber.org/zap"
)

func TestDevizeSubmissionStrategy(t *testing.T) {
	cfg := config.MustLoad()
	s := New(cfg, zap.NewNop(), monitor.New(cfg))

	for _, entryType := range []ctgo.LogEntryType{ctgo.X509LogEntryType, ctgo.PrecertLogEntryType} {
		strategy := s.devizeSubmissionStrategy(loglists.UsableTLSLogs, entryType)
		if len(strategy) == 0 {
			t.Fatalf("expected a non-empty strategy from the usable TLS log list (entryType %v)", entryType)
		}
		// Members must be sorted by bucket descending.
		for i := 1; i < len(strategy); i++ {
			if strategy[i-1].Bucket < strategy[i].Bucket {
				t.Errorf("strategy not sorted by bucket: index %d (%v) < index %d (%v)", i-1, strategy[i-1].Bucket, i, strategy[i].Bucket)
			}
		}
	}
}

func TestApplyLogExclusionConfig(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`example\.com`)}

	sm := StrategyMember{Bucket: NEUTRAL}
	sm.applyLogExclusionConfig("https://ct.example.com/", regexes)
	if sm.Bucket != EXCLUDED {
		t.Errorf("matching URL: got bucket %v, want EXCLUDED", sm.Bucket)
	}

	unmatched := StrategyMember{Bucket: NEUTRAL}
	unmatched.applyLogExclusionConfig("https://ct.other.test/", regexes)
	if unmatched.Bucket != NEUTRAL {
		t.Errorf("non-matching URL: got bucket %v, want NEUTRAL", unmatched.Bucket)
	}
}

func TestApplyLogPreferenceConfig(t *testing.T) {
	regexes := []*regexp.Regexp{regexp.MustCompile(`example\.com`)}

	sm := StrategyMember{Bucket: NEUTRAL}
	sm.applyLogPreferenceConfig("https://ct.example.com/", regexes)
	if sm.Bucket != PREFERRED_BYCONFIG {
		t.Errorf("matching URL: got bucket %v, want PREFERRED_BYCONFIG", sm.Bucket)
	}

	excluded := StrategyMember{Bucket: EXCLUDED}
	excluded.applyLogPreferenceConfig("https://ct.example.com/", regexes)
	if excluded.Bucket != EXCLUDED {
		t.Errorf("excluded member should not be promoted: got bucket %v", excluded.Bucket)
	}
}

func TestSortStrategyMembers(t *testing.T) {
	// Higher bucket sorts first (negative result).
	if got := sortStrategyMembers(StrategyMember{Bucket: PREFERRED_BYCONFIG}, StrategyMember{Bucket: NEUTRAL}); got >= 0 {
		t.Errorf("PREFERRED_BYCONFIG should sort before NEUTRAL: got %d", got)
	}
	// Same bucket: lower RandomWeight sorts first.
	if got := sortStrategyMembers(StrategyMember{Bucket: NEUTRAL, RandomWeight: 1}, StrategyMember{Bucket: NEUTRAL, RandomWeight: 2}); got >= 0 {
		t.Errorf("lower RandomWeight should sort first: got %d", got)
	}
	// Identical members compare equal.
	if got := sortStrategyMembers(StrategyMember{Bucket: NEUTRAL, RandomWeight: 5}, StrategyMember{Bucket: NEUTRAL, RandomWeight: 5}); got != 0 {
		t.Errorf("identical members should compare equal: got %d", got)
	}
}

func TestDispreferralFromBackoff(t *testing.T) {
	cfg := config.MustLoad()
	mon := monitor.New(cfg)
	const url = "https://ct.backoff-test.example/"

	mon.RecordBadResponse(url, errors.New("bad"))
	sm := StrategyMember{SubmissionURL: url, Bucket: NEUTRAL}
	sm.dispreferIfBadResponseBackoff(mon)
	if sm.Bucket != DISPREFERRED_RECENTBADRESPONSE {
		t.Errorf("bad response: got bucket %v, want DISPREFERRED_RECENTBADRESPONSE", sm.Bucket)
	}

	mon.RecordTimeout(url, errors.New("timeout"))
	sm = StrategyMember{SubmissionURL: url, Bucket: NEUTRAL}
	sm.dispreferIfTimeoutBackoff(mon)
	if sm.Bucket != DISPREFERRED_RECENTTIMEOUT {
		t.Errorf("timeout: got bucket %v, want DISPREFERRED_RECENTTIMEOUT", sm.Bucket)
	}

	mon.Record5xxResponse(url, &http.Response{StatusCode: 503, Header: http.Header{}})
	sm = StrategyMember{SubmissionURL: url, Bucket: NEUTRAL}
	sm.dispreferIf5xxBackoff(mon)
	if sm.Bucket != DISPREFERRED_RECENT5XX {
		t.Errorf("5xx: got bucket %v, want DISPREFERRED_RECENT5XX", sm.Bucket)
	}

	mon.Record4xxResponse(url, &http.Response{StatusCode: 429, Header: http.Header{}})
	sm = StrategyMember{SubmissionURL: url, Bucket: NEUTRAL}
	sm.dispreferIf4xxBackoff(mon)
	if sm.Bucket != DISPREFERRED_RECENT4XX {
		t.Errorf("4xx: got bucket %v, want DISPREFERRED_RECENT4XX", sm.Bucket)
	}

	mon.RecordSlowResponse(url)
	sm = StrategyMember{SubmissionURL: url, Bucket: NEUTRAL}
	sm.dispreferIfSlowResponseBackoff(mon)
	if sm.Bucket != DISPREFERRED_SLOWRESPONSES {
		t.Errorf("slow response: got bucket %v, want DISPREFERRED_SLOWRESPONSES", sm.Bucket)
	}
}

func TestDispreferIfMMDBlownWithoutData(t *testing.T) {
	cfg := config.MustLoad()
	mon := monitor.New(cfg)

	sm := StrategyMember{MonitoringURL: "https://ct.unknown.example/", Bucket: NEUTRAL}
	sm.dispreferIfMMDBlown(mon)
	if sm.Bucket != EXCLUDED {
		t.Errorf("unknown log without STH data should be EXCLUDED: got %v", sm.Bucket)
	}
}

func TestDispreferIfLowUptimeWithoutData(t *testing.T) {
	cfg := config.MustLoad()
	mon := monitor.New(cfg)

	// Unknown URLs have no uptime data, so the member is left unchanged.
	for _, entryType := range []ctgo.LogEntryType{ctgo.X509LogEntryType, ctgo.PrecertLogEntryType} {
		sm := StrategyMember{SubmissionURL: "https://ct.unknown.example/", Bucket: NEUTRAL}
		sm.dispreferIfLowUptime(entryType, mon, cfg)
		if sm.Bucket != NEUTRAL {
			t.Errorf("entryType %v: expected NEUTRAL without uptime data, got %v", entryType, sm.Bucket)
		}
	}
}

func TestCompileRegexes(t *testing.T) {
	res := compileRegexes([]string{`^https://a/`, `b\.example`})
	if len(res) != 2 {
		t.Fatalf("compileRegexes: got %d, want 2", len(res))
	}
	if !res[0].MatchString("https://a/") || !res[1].MatchString("https://b.example/") {
		t.Error("compiled regexes did not match expected inputs")
	}
	if got := compileRegexes(nil); got != nil {
		t.Errorf("compileRegexes(nil): got %v, want nil", got)
	}
}
