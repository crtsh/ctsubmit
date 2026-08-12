package config

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestParseResponseFormat(t *testing.T) {
	cases := []struct {
		in   string
		want ResponseFormat
	}{
		{"html", RESPONSEFORMAT_HTML},
		{"HTML", RESPONSEFORMAT_HTML},
		{"json", RESPONSEFORMAT_JSON},
		{"JSON", RESPONSEFORMAT_JSON},
		{"xml", -1},
		{"", -1},
	}
	for _, c := range cases {
		if got := ParseResponseFormat(c.in); got != c.want {
			t.Errorf("ParseResponseFormat(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}
	if cfg.Server.WebserverPort != 8080 {
		t.Errorf("Server.WebserverPort: got %d, want 8080", cfg.Server.WebserverPort)
	}
	if cfg.Strategy.Submission.HTTPTimeout != 15*time.Second {
		t.Errorf("Strategy.Submission.HTTPTimeout: got %v, want 15s", cfg.Strategy.Submission.HTTPTimeout)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestMustLoad(t *testing.T) {
	if cfg := MustLoad(); cfg == nil {
		t.Fatal("MustLoad() returned nil")
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	base := MustLoad()
	if err := base.validate(); err != nil {
		t.Fatalf("baseline config should be valid: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(s *Settings)
	}{
		{"submitEndpoint24h above 100", func(s *Settings) { s.Strategy.UptimeThreshold.SubmitEndpoint24h = 101 }},
		{"submitEndpoint24h negative", func(s *Settings) { s.Strategy.UptimeThreshold.SubmitEndpoint24h = -1 }},
		{"lowestEndpoint90d below 99", func(s *Settings) { s.Strategy.UptimeThreshold.LowestEndpoint90d = 98 }},
		{"lowestEndpoint90d above 100", func(s *Settings) { s.Strategy.UptimeThreshold.LowestEndpoint90d = 101 }},
		{"badResponsePeriod negative", func(s *Settings) { s.Strategy.Backoff.BadResponsePeriod = -time.Second }},
		{"timeoutPeriod negative", func(s *Settings) { s.Strategy.Backoff.TimeoutPeriod = -time.Second }},
		{"default5xxPeriod negative", func(s *Settings) { s.Strategy.Backoff.Default5xxPeriod = -time.Second }},
		{"default4xxPeriod negative", func(s *Settings) { s.Strategy.Backoff.Default4xxPeriod = -time.Second }},
		{"slowResponsePeriod negative", func(s *Settings) { s.Strategy.Backoff.SlowResponsePeriod = -time.Second }},
		{"tryNextResponseThreshold zero", func(s *Settings) { s.Strategy.Submission.TryNextResponseThreshold = 0 }},
		{"slowResponseThreshold zero", func(s *Settings) { s.Strategy.Submission.SlowResponseThreshold = 0 }},
		{"submission httpTimeout zero", func(s *Settings) { s.Strategy.Submission.HTTPTimeout = 0 }},
		{"sthMonitor refreshInterval zero", func(s *Settings) { s.STHMonitor.RefreshInterval = 0 }},
		{"sthMonitor httpTimeout zero", func(s *Settings) { s.STHMonitor.HTTPTimeout = 0 }},
		{"uptimeFetcher refreshInterval zero", func(s *Settings) { s.UptimeFetcher.RefreshInterval = 0 }},
		{"uptimeFetcher httpTimeout zero", func(s *Settings) { s.UptimeFetcher.HTTPTimeout = 0 }},
		{"no response output enabled", func(s *Settings) {
			s.Response.IncludeLogResponses = false
			s.Response.IncludeSCTList = false
			s.Response.ProduceFinalTBSCert = false
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := *base
			tc.mutate(&s)
			if err := s.validate(); err == nil {
				t.Errorf("expected a validation error for %q", tc.name)
			}
		})
	}
}

func TestLogStartupInfo(t *testing.T) {
	// Should not panic when given a usable logger.
	LogStartupInfo(zap.NewNop())
}
