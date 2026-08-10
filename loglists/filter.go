package loglists

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/crtsh/ctsubmit/config"

	"github.com/crtsh/ctloglists"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"golang.org/x/mod/semver"
)

var UsableTLSLogs, ActiveTLSLogs, TestTLSLogs, UsableBIMILogs *loglist3.LogList

var _ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "loglist",
	Name:      "oldest_timestamp_age_seconds",
	Help:      "Age in seconds of the oldest log list timestamp among lists with a 70-day enforcement cut-off.",
}, func() float64 {
	oldest := ctloglists.OldestTimestampForLogListWithEnforcementCutOff()
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest).Seconds()
})

func init() {
	if err := ctloglists.LoadAcceptedRoots(); err != nil {
		panic(fmt.Sprintf("failed to load accepted roots: %v", err))
	}
	if err := ctloglists.LoadLogLists(); err != nil {
		panic(fmt.Sprintf("failed to load log lists: %v", err))
	}

	determineUsableTLSLogs()
	determineActiveTLSLogs()
	determineTestTLSLogs()
	determineUsableBIMILogs()

	// Use the github.com/crtsh/ctloglists release version timestamp as the log lists' timestamp.
	if logListTimestamp, err := getCtloglistsReleaseTimestamp(); err == nil {
		UsableTLSLogs.LogListTimestamp = logListTimestamp
		ActiveTLSLogs.LogListTimestamp = logListTimestamp
		TestTLSLogs.LogListTimestamp = logListTimestamp
		UsableBIMILogs.LogListTimestamp = logListTimestamp
	}
}

// getCtloglistsReleaseTimestamp extracts the release timestamp from the ctloglists module version.
// The version format is vMajor.YYYYMMDD.HHMMSS (e.g., v1.20260421.211344), where any leading zeroes in HHMMSS are stripped.
func getCtloglistsReleaseTimestamp() (time.Time, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return time.Time{}, fmt.Errorf("failed to read build info")
	}

	for _, dep := range bi.Deps {
		if dep.Path == "github.com/crtsh/ctloglists" {
			v := dep.Version
			if !semver.IsValid(v) {
				return time.Time{}, fmt.Errorf("invalid semver version: %s", v)
			}
			// Strip the "v" prefix and split into major.YYYYMMDD.HHMMSS.
			parts := strings.SplitN(v[1:], ".", 3)
			if len(parts) != 3 {
				return time.Time{}, fmt.Errorf("unexpected version format: %s", v)
			}
			// Left-pad parts[2] with zeroes to ensure it's always 6 digits (HHMMSS).
			hhmmss := fmt.Sprintf("%06s", parts[2])
			// Parse the timestamp in UTC.
			t, err := time.Parse("20060102.150405", parts[1]+"."+hhmmss)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse timestamp from version %s: %w", v, err)
			}
			return t.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("ctloglists dependency not found in build info")
}

func determineUsableTLSLogs() {
	chromeUsableLogs := ctloglists.GstaticV3All.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	appleUsableLogs := ctloglists.AppleCurrent.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})

	// MozillaAdmissibleLogs retains both Qualified and Usable status transitions, and SelectByStatus will only see the first one.
	// Qualified / future-Usable logs will be filtered out per-request.
	mozillaAdmissibleLogs := ctloglists.MozillaV3Known.SelectByStatus([]loglist3.LogStatus{loglist3.QualifiedLogStatus, loglist3.UsableLogStatus})

	UsableTLSLogs = intersect(intersect(&chromeUsableLogs, &appleUsableLogs), &mozillaAdmissibleLogs)
	useCrtshLogNames(UsableTLSLogs)
}

func determineActiveTLSLogs() {
	ActiveTLSLogs = &loglist3.LogList{}
	for _, operator := range ctloglists.CrtshV3Active.Operators {
		op := *operator
		op.Logs = []*loglist3.Log{}
		for _, log := range operator.Logs {
			if log.Type != "test" && ctloglists.BimiV3Approved.FindLogByURL(log.URL) == nil {
				op.Logs = append(op.Logs, log)
			}
		}
		op.TiledLogs = []*loglist3.TiledLog{}
		for _, tiledLog := range operator.TiledLogs {
			if tiledLog.Type != "test" {
				op.TiledLogs = append(op.TiledLogs, tiledLog)
			}
		}
		if len(op.Logs) > 0 || len(op.TiledLogs) > 0 {
			ActiveTLSLogs.Operators = append(ActiveTLSLogs.Operators, &op)
		}
	}
}

func determineTestTLSLogs() {
	TestTLSLogs = &loglist3.LogList{}
	for _, operator := range ctloglists.CrtshV3Active.Operators {
		op := *operator
		op.Logs = []*loglist3.Log{}
		for _, log := range operator.Logs {
			if log.Type == "test" && ctloglists.BimiV3Approved.FindTiledLogByURL(log.URL) == nil {
				op.Logs = append(op.Logs, log)
			}
		}
		op.TiledLogs = []*loglist3.TiledLog{}
		for _, tiledLog := range operator.TiledLogs {
			if tiledLog.Type == "test" {
				op.TiledLogs = append(op.TiledLogs, tiledLog)
			}
		}
		if len(op.Logs) > 0 || len(op.TiledLogs) > 0 {
			TestTLSLogs.Operators = append(TestTLSLogs.Operators, &op)
		}
	}
}

func determineUsableBIMILogs() {
	usableBimiLogs := ctloglists.BimiV3Approved.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus})
	UsableBIMILogs = &usableBimiLogs
	useCrtshLogNames(UsableBIMILogs)
}

func intersect(ll1 *loglist3.LogList, ll2 *loglist3.LogList) *loglist3.LogList {
	intersection := &loglist3.LogList{}
	for _, operator1 := range ll1.Operators {
		op := *operator1
		op.Logs = []*loglist3.Log{}
		for _, operator2 := range ll2.Operators {
			for _, log1 := range operator1.Logs {
				for _, log2 := range operator2.Logs {
					if bytes.Equal(log1.LogID, log2.LogID) && !strings.Contains(log1.URL, "bogus") {
						if log1.State.Usable != nil && log2.State.Usable != nil && log2.State.Usable.Timestamp.After(log1.State.Usable.Timestamp) {
							log1.State.Usable.Timestamp = log2.State.Usable.Timestamp
						}
						if log1.TemporalInterval != nil && log2.TemporalInterval != nil {
							if log2.TemporalInterval.StartInclusive.After(log1.TemporalInterval.StartInclusive) {
								log1.TemporalInterval.StartInclusive = log2.TemporalInterval.StartInclusive
							}
							if log2.TemporalInterval.EndExclusive.Before(log1.TemporalInterval.EndExclusive) {
								log1.TemporalInterval.EndExclusive = log2.TemporalInterval.EndExclusive
							}
						}
						op.Logs = append(op.Logs, log1)
						break
					}
				}
			}
		}
		op.TiledLogs = []*loglist3.TiledLog{}
		for _, tiledLog1 := range operator1.TiledLogs {
			for _, operator2 := range ll2.Operators {
				for _, tiledLog2 := range operator2.TiledLogs {
					if bytes.Equal(tiledLog1.LogID, tiledLog2.LogID) {
						if tiledLog1.State.Usable != nil && tiledLog2.State.Usable != nil && tiledLog2.State.Usable.Timestamp.After(tiledLog1.State.Usable.Timestamp) {
							tiledLog1.State.Usable.Timestamp = tiledLog2.State.Usable.Timestamp
						}
						if tiledLog1.TemporalInterval != nil && tiledLog2.TemporalInterval != nil {
							if tiledLog2.TemporalInterval.StartInclusive.After(tiledLog1.TemporalInterval.StartInclusive) {
								tiledLog1.TemporalInterval.StartInclusive = tiledLog2.TemporalInterval.StartInclusive
							}
							if tiledLog2.TemporalInterval.EndExclusive.Before(tiledLog1.TemporalInterval.EndExclusive) {
								tiledLog1.TemporalInterval.EndExclusive = tiledLog2.TemporalInterval.EndExclusive
							}
						}
						op.TiledLogs = append(op.TiledLogs, tiledLog1)
						break
					}
				}
			}
		}
		if len(op.Logs) > 0 || len(op.TiledLogs) > 0 {
			intersection.Operators = append(intersection.Operators, &op)
		}
	}
	return intersection
}
