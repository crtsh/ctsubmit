package monitor

import (
	"time"

	"github.com/crtsh/ctsubmit/config"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var submissionOutcomeCounter = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "submission",
	Name:      "outcome_total",
	Help:      "Total submission outcomes per log, by outcome.",
}, []string{"url", "outcome"})

// RecordSubmissionOutcome increments the Prometheus counter for a submission outcome.
func (m *Monitor) RecordSubmissionOutcome(submissionURL string, outcome string) {
	submissionOutcomeCounter.WithLabelValues(submissionURL, outcome).Inc()
	m.recordOutcomeSample(submissionURL, outcome)
}

// outcomeSample is a single recorded outcome with its timestamp.
type outcomeSample struct {
	at      time.Time
	success bool
}

func (m *Monitor) recordOutcomeSample(submissionURL string, outcome string) {
	// Cancelled submissions never received a response, so don't count them.
	if outcome == "cancelled" {
		return
	}
	m.outcomeSamplesMutex.Lock()
	defer m.outcomeSamplesMutex.Unlock()
	now := time.Now()
	cutoff := now.Add(-responseTimeWindow)
	samples := m.outcomeSamples[submissionURL]
	i := 0
	for i < len(samples) && samples[i].at.Before(cutoff) {
		i++
	}
	m.outcomeSamples[submissionURL] = append(samples[i:], outcomeSample{at: now, success: outcome == "success"})
}

// GetRecentOutcomeCounts returns the number of successful and failed responses in the last 30s.
func (m *Monitor) GetRecentOutcomeCounts(submissionURL string) (successes, failures int) {
	m.outcomeSamplesMutex.Lock()
	defer m.outcomeSamplesMutex.Unlock()
	cutoff := time.Now().Add(-responseTimeWindow)
	samples := m.outcomeSamples[submissionURL]
	i := 0
	for i < len(samples) && samples[i].at.Before(cutoff) {
		i++
	}
	samples = samples[i:]
	m.outcomeSamples[submissionURL] = samples
	for _, s := range samples {
		if s.success {
			successes++
		} else {
			failures++
		}
	}
	return
}

var submissionResponseTime = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Namespace: config.ApplicationNamespace,
	Subsystem: "submission",
	Name:      "response_seconds",
	Help:      "Per-log submission response time in seconds (excludes cancelled submissions).",
	Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
}, []string{"url"})

// RecordSubmissionResponseTime observes a response time for the given log.
func (m *Monitor) RecordSubmissionResponseTime(submissionURL string, d time.Duration) {
	submissionResponseTime.WithLabelValues(submissionURL).Observe(d.Seconds())
	m.recordResponseTimeSample(submissionURL, d)
}

// responseTimeSample is a single recorded response time with its timestamp.
type responseTimeSample struct {
	at       time.Time
	duration time.Duration
}

const responseTimeWindow = 30 * time.Second

func (m *Monitor) recordResponseTimeSample(submissionURL string, d time.Duration) {
	m.responseTimeSamplesMutex.Lock()
	defer m.responseTimeSamplesMutex.Unlock()
	now := time.Now()
	cutoff := now.Add(-responseTimeWindow)
	samples := m.responseTimeSamples[submissionURL]
	// Drop samples older than the window.
	i := 0
	for i < len(samples) && samples[i].at.Before(cutoff) {
		i++
	}
	m.responseTimeSamples[submissionURL] = append(samples[i:], responseTimeSample{at: now, duration: d})
}

// GetAvgResponseTime returns the average response time over the last 30s for a log.
func (m *Monitor) GetAvgResponseTime(submissionURL string) (time.Duration, bool) {
	m.responseTimeSamplesMutex.Lock()
	defer m.responseTimeSamplesMutex.Unlock()
	cutoff := time.Now().Add(-responseTimeWindow)
	samples := m.responseTimeSamples[submissionURL]
	// Drop stale samples.
	i := 0
	for i < len(samples) && samples[i].at.Before(cutoff) {
		i++
	}
	samples = samples[i:]
	m.responseTimeSamples[submissionURL] = samples
	if len(samples) == 0 {
		return 0, false
	}
	var total time.Duration
	for _, s := range samples {
		total += s.duration
	}
	return total / time.Duration(len(samples)), true
}
