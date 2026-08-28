package loglists

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/crtsh/ctsubmit/config"

	"github.com/crtsh/ctloglists"
)

// writeCustomTestLogList writes a minimal v3 log list JSON file containing one
// RFC6962 log with a freshly generated key, and returns its path and log ID.
func writeCustomTestLogList(t *testing.T, timestamp string) (string, [sha256.Size]byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	logList := map[string]any{
		"operators": []any{
			map[string]any{
				"name":  "Test Operator",
				"email": []string{"test@example.com"},
				"logs": []any{
					map[string]any{
						"description": "Custom Test Log",
						"log_id":      base64.StdEncoding.EncodeToString(func() []byte { h := sha256.Sum256(spki); return h[:] }()),
						"key":         base64.StdEncoding.EncodeToString(spki),
						"url":         "https://custom.test.log.example.com/",
						"mmd":         86400,
					},
				},
			},
		},
	}
	if timestamp != "" {
		logList["log_list_timestamp"] = timestamp
	}

	data, err := json.Marshal(logList)
	if err != nil {
		t.Fatalf("failed to marshal log list: %v", err)
	}

	path := filepath.Join(t.TempDir(), "test_log_list.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("failed to write log list: %v", err)
	}

	return path, sha256.Sum256(spki)
}

// restoreGlobals reverts the process-global state that LoadCustomTestLogList mutates.
func restoreGlobals(t *testing.T, logID [sha256.Size]byte) {
	t.Helper()
	original := TestTLSLogs
	t.Cleanup(func() {
		TestTLSLogs = original
		customTestLogList = nil
		delete(ctloglists.LogSignatureVerifierMap, logID)
	})
}

func TestLoadCustomTestLogListNotConfigured(t *testing.T) {
	original := TestTLSLogs
	var cfg config.Settings
	if err := LoadCustomTestLogList(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if TestTLSLogs != original {
		t.Error("TestTLSLogs was replaced even though no custom test log list was configured")
	}
	if CustomTestLogList() != nil {
		t.Error("CustomTestLogList should be nil when no custom test log list was configured")
	}
}

func TestLoadCustomTestLogListOverridesTestLogs(t *testing.T) {
	path, logID := writeCustomTestLogList(t, "2026-01-02T03:04:05Z")
	restoreGlobals(t, logID)

	var cfg config.Settings
	cfg.Strategy.TestLogListFilename = path
	if err := LoadCustomTestLogList(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(TestTLSLogs.Operators) != 1 || len(TestTLSLogs.Operators[0].Logs) != 1 {
		t.Fatalf("expected 1 operator with 1 log, got %+v", TestTLSLogs.Operators)
	}
	if got := TestTLSLogs.Operators[0].Logs[0].Description; got != "Custom Test Log" {
		t.Errorf("unexpected log description: %q", got)
	}
	if TestTLSLogs.LogListTimestamp.IsZero() {
		t.Error("expected the log list timestamp from the JSON to be retained")
	}
	if ctloglists.LogSignatureVerifierMap[logID] == nil {
		t.Error("expected a signature verifier to be registered for the custom log")
	}
	if CustomTestLogList() != TestTLSLogs {
		t.Error("expected CustomTestLogList to return the loaded log list")
	}
	if operator, description := GetLogName(logID[:]); operator != "Test Operator" || description != "Custom Test Log" {
		t.Errorf("GetLogName returned (%q, %q)", operator, description)
	}
}

func TestLoadCustomTestLogListTimestampFallsBackToFileModTime(t *testing.T) {
	path, logID := writeCustomTestLogList(t, "")
	restoreGlobals(t, logID)

	var cfg config.Settings
	cfg.Strategy.TestLogListFilename = path
	if err := LoadCustomTestLogList(&cfg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if TestTLSLogs.LogListTimestamp.IsZero() {
		t.Error("expected the log list timestamp to fall back to the file's modification time")
	}
}

func TestLoadCustomTestLogListErrors(t *testing.T) {
	badJSONPath := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(badJSONPath, []byte("not json"), 0o600); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	for name, path := range map[string]string{
		"missing file": filepath.Join(t.TempDir(), "does_not_exist.json"),
		"unparseable":  badJSONPath,
	} {
		t.Run(name, func(t *testing.T) {
			original := TestTLSLogs
			var cfg config.Settings
			cfg.Strategy.TestLogListFilename = path
			if err := LoadCustomTestLogList(&cfg); err == nil {
				t.Error("expected an error")
			}
			if TestTLSLogs != original {
				t.Error("TestTLSLogs was replaced despite the error")
			}
		})
	}
}
