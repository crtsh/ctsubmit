package monitor

import "testing"

func TestCheckpointKeyName(t *testing.T) {
	tests := map[string]string{
		"https://log.example.com/":     "log.example.com",
		"https://log.example.com/2026": "log.example.com/2026",
		"http://127.0.0.1:6962/":       "127.0.0.1:6962",
		"http://127.0.0.1:6962":        "127.0.0.1:6962",
		"log.example.com/":             "log.example.com",
	}

	for submissionURL, want := range tests {
		if got := checkpointKeyName(submissionURL); got != want {
			t.Errorf("checkpointKeyName(%q) = %q, want %q", submissionURL, got, want)
		}
	}
}
