package loglists

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/crtsh/ctsubmit/config"

	"github.com/crtsh/ctloglists"
	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

// customTestLogList is non-nil once a custom test log list has replaced TestTLSLogs.
var customTestLogList *loglist3.LogList

// CustomTestLogList returns the log list loaded from strategy.testLogListFilename, or nil if that option isn't set.
func CustomTestLogList() *loglist3.LogList {
	return customTestLogList
}

// LoadCustomTestLogList replaces TestTLSLogs with the log list parsed from
// cfg.Strategy.TestLogListFilename, when that option is set. It is a no-op
// otherwise. Call it after config.Load and before monitor.New, so that the
// monitor's caches are seeded for the custom logs.
func LoadCustomTestLogList(cfg *config.Settings) error {
	if cfg.Strategy.TestLogListFilename == "" {
		return nil
	}

	data, err := os.ReadFile(cfg.Strategy.TestLogListFilename)
	if err != nil {
		return fmt.Errorf("failed to read custom test log list %q: %w", cfg.Strategy.TestLogListFilename, err)
	}

	logList, err := loglist3.NewFromJSON(data)
	if err != nil {
		return fmt.Errorf("failed to parse custom test log list %q: %w", cfg.Strategy.TestLogListFilename, err)
	}

	if err := validateLogList(logList); err != nil {
		return fmt.Errorf("invalid custom test log list %q: %w", cfg.Strategy.TestLogListFilename, err)
	}

	// SCT signature verification looks logs up by key ID, so the custom logs must be registered even if ctloglists doesn't know them.
	if err := registerSignatureVerifiers(logList); err != nil {
		return fmt.Errorf("failed to register signature verifiers for custom test log list %q: %w", cfg.Strategy.TestLogListFilename, err)
	}

	// Fall back to the file's modification time when the JSON omits log_list_timestamp.
	if logList.LogListTimestamp.IsZero() {
		if fi, err := os.Stat(cfg.Strategy.TestLogListFilename); err == nil {
			logList.LogListTimestamp = fi.ModTime().UTC()
		}
	}

	TestTLSLogs = logList
	customTestLogList = logList
	return nil
}

// validateLogList checks the fields that the rest of ctsubmit relies on but loglist3.NewFromJSON doesn't enforce.
func validateLogList(logList *loglist3.LogList) error {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if log.URL == "" {
				return fmt.Errorf("log %q: url is required", log.Description)
			}
			if err := validateLogID(log.LogID, log.Key); err != nil {
				return fmt.Errorf("log %q: %w", log.Description, err)
			}
		}
		for _, tiledLog := range operator.TiledLogs {
			if tiledLog.SubmissionURL == "" {
				return fmt.Errorf("tiled log %q: submission_url is required", tiledLog.Description)
			}
			if tiledLog.MonitoringURL == "" {
				return fmt.Errorf("tiled log %q: monitoring_url is required", tiledLog.Description)
			}
			if err := validateLogID(tiledLog.LogID, tiledLog.Key); err != nil {
				return fmt.Errorf("tiled log %q: %w", tiledLog.Description, err)
			}
		}
	}
	return nil
}

// validateLogID guards against log_id and key disagreeing, since SCT verification keys off the latter while chain validation keys off the former.
func validateLogID(logID, key []byte) error {
	expected := sha256.Sum256(key)
	if !bytes.Equal(logID, expected[:]) {
		return fmt.Errorf("log_id is %q, but the SHA-256 hash of key is %q", base64.StdEncoding.EncodeToString(logID), base64.StdEncoding.EncodeToString(expected[:]))
	}
	return nil
}

func registerSignatureVerifiers(logList *loglist3.LogList) error {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if err := registerSignatureVerifier(log.Key); err != nil {
				return fmt.Errorf("log %q: %w", log.URL, err)
			}
		}
		for _, tiledLog := range operator.TiledLogs {
			if err := registerSignatureVerifier(tiledLog.Key); err != nil {
				return fmt.Errorf("log %q: %w", tiledLog.SubmissionURL, err)
			}
		}
	}
	return nil
}

func registerSignatureVerifier(logPublicKey []byte) error {
	logID := sha256.Sum256(logPublicKey)
	if ctloglists.LogSignatureVerifierMap[logID] != nil {
		return nil
	}

	publicKey, err := x509.ParsePKIXPublicKey(logPublicKey)
	if err != nil {
		return err
	}
	sv, err := ctgo.NewSignatureVerifier(publicKey)
	if err != nil {
		return err
	}

	ctloglists.LogSignatureVerifierMap[logID] = sv
	return nil
}
