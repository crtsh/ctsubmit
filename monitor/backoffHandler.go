package monitor

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/crtsh/ctsubmit/logger"

	"github.com/crtsh/ctloglists"

	"go.uber.org/zap"
)

type backoffEntry struct {
	BackoffUntil  time.Time
	BackoffPeriod time.Duration
	StatusCode    int
}

func (m *Monitor) initBackoffMaps() {
	for _, operator := range ctloglists.CrtshV3Active.Operators {
		for _, log := range operator.Logs {
			submissionURL, _ := url.JoinPath(log.URL, "/")
			m.backoffBadResponse[submissionURL] = &backoffEntry{}
			m.backoffTimeout[submissionURL] = &backoffEntry{}
			m.backoff5xx[submissionURL] = &backoffEntry{}
			m.backoff4xx[submissionURL] = &backoffEntry{}
			m.backoffSlowResponse[submissionURL] = &backoffEntry{}
		}
		for _, tiledLog := range operator.TiledLogs {
			submissionURL, _ := url.JoinPath(tiledLog.SubmissionURL, "/")
			m.backoffBadResponse[submissionURL] = &backoffEntry{}
			m.backoffTimeout[submissionURL] = &backoffEntry{}
			m.backoff5xx[submissionURL] = &backoffEntry{}
			m.backoff4xx[submissionURL] = &backoffEntry{}
			m.backoffSlowResponse[submissionURL] = &backoffEntry{}
		}
	}
}

func (m *Monitor) RecordBadResponse(submissionURL string, err error) bool {
	logger.Logger.Warn("Bad response", zap.String("url", submissionURL), zap.Error(err))

	m.mutexBadResponse.Lock()
	defer m.mutexBadResponse.Unlock()

	boBad, ok := m.backoffBadResponse[submissionURL]
	if !ok {
		boBad = &backoffEntry{}
		m.backoffBadResponse[submissionURL] = boBad
	}

	backoffUntil := time.Now().Add(m.cfg.Strategy.Backoff.BadResponsePeriod)
	if boBad.BackoffUntil.Before(backoffUntil) {
		boBad.BackoffUntil = backoffUntil
		boBad.BackoffPeriod = m.cfg.Strategy.Backoff.BadResponsePeriod
	}

	return true
}

func (m *Monitor) RecordTimeout(submissionURL string, err error) bool {
	logger.Logger.Warn("Connection timeout", zap.String("url", submissionURL), zap.Error(err))

	m.mutexTimeout.Lock()
	defer m.mutexTimeout.Unlock()

	boTimeout, ok := m.backoffTimeout[submissionURL]
	if !ok {
		boTimeout = &backoffEntry{}
		m.backoffTimeout[submissionURL] = boTimeout
	}

	backoffUntil := time.Now().Add(m.cfg.Strategy.Backoff.TimeoutPeriod)
	if boTimeout.BackoffUntil.Before(backoffUntil) {
		boTimeout.BackoffUntil = backoffUntil
		boTimeout.BackoffPeriod = m.cfg.Strategy.Backoff.TimeoutPeriod
	}

	return true
}

func (m *Monitor) Record5xxResponse(submissionURL string, httpResponse *http.Response) bool {
	logger.Logger.Warn("HTTP server error", zap.Int("status_code", httpResponse.StatusCode), zap.String("url", submissionURL))

	backoffDuration := m.cfg.Strategy.Backoff.Default5xxPeriod
	if retryAfter := parseRetryAfter(httpResponse); retryAfter > 0 {
		backoffDuration = retryAfter
	}

	m.mutex5xx.Lock()
	defer m.mutex5xx.Unlock()

	bo5xx, ok := m.backoff5xx[submissionURL]
	if !ok {
		bo5xx = &backoffEntry{}
		m.backoff5xx[submissionURL] = bo5xx
	}

	backoffUntil := time.Now().Add(backoffDuration)
	if bo5xx.BackoffUntil.Before(backoffUntil) {
		bo5xx.BackoffUntil = backoffUntil
		bo5xx.BackoffPeriod = backoffDuration
		bo5xx.StatusCode = httpResponse.StatusCode
	}

	return true
}

func (m *Monitor) Record4xxResponse(submissionURL string, httpResponse *http.Response) bool {
	logger.Logger.Warn("HTTP client error", zap.Int("status_code", httpResponse.StatusCode), zap.String("url", submissionURL))

	backoffDuration := m.cfg.Strategy.Backoff.Default4xxPeriod
	if retryAfter := parseRetryAfter(httpResponse); retryAfter > 0 {
		backoffDuration = retryAfter
	}

	m.mutex4xx.Lock()
	defer m.mutex4xx.Unlock()

	bo4xx, ok := m.backoff4xx[submissionURL]
	if !ok {
		bo4xx = &backoffEntry{}
		m.backoff4xx[submissionURL] = bo4xx
	}

	backoffUntil := time.Now().Add(backoffDuration)
	if bo4xx.BackoffUntil.Before(backoffUntil) {
		bo4xx.BackoffUntil = backoffUntil
		bo4xx.BackoffPeriod = backoffDuration
		bo4xx.StatusCode = httpResponse.StatusCode
	}

	return true
}

func (m *Monitor) RecordSlowResponse(submissionURL string) bool {
	logger.Logger.Warn("Slow response", zap.String("url", submissionURL))

	m.mutexSlowResponse.Lock()
	defer m.mutexSlowResponse.Unlock()

	boSlow, ok := m.backoffSlowResponse[submissionURL]
	if !ok {
		boSlow = &backoffEntry{}
		m.backoffSlowResponse[submissionURL] = boSlow
	}

	backoffUntil := time.Now().Add(m.cfg.Strategy.Backoff.SlowResponsePeriod)
	if boSlow.BackoffUntil.Before(backoffUntil) {
		boSlow.BackoffUntil = backoffUntil
		boSlow.BackoffPeriod = m.cfg.Strategy.Backoff.SlowResponsePeriod
	}
	return true
}

func (m *Monitor) GetBadResponseBackoff(submissionURL string) (time.Duration, string) {
	m.mutexBadResponse.RLock()
	defer m.mutexBadResponse.RUnlock()

	boBad, ok := m.backoffBadResponse[submissionURL]
	if !ok || time.Now().After(boBad.BackoffUntil) {
		return 0, ""
	}

	return time.Until(boBad.BackoffUntil), fmt.Sprintf("Backoff until %s due to recent bad response", boBad.BackoffUntil.Format(time.RFC1123))
}

func (m *Monitor) GetTimeoutBackoff(submissionURL string) (time.Duration, string) {
	m.mutexTimeout.RLock()
	defer m.mutexTimeout.RUnlock()

	boTimeout, ok := m.backoffTimeout[submissionURL]
	if !ok || time.Now().After(boTimeout.BackoffUntil) {
		return 0, ""
	}

	return time.Until(boTimeout.BackoffUntil), fmt.Sprintf("Backoff until %s due to recent timeout", boTimeout.BackoffUntil.Format(time.RFC1123))
}

func (m *Monitor) Get5xxBackoff(submissionURL string) (time.Duration, string, int) {
	m.mutex5xx.RLock()
	defer m.mutex5xx.RUnlock()

	bo5xx, ok := m.backoff5xx[submissionURL]
	if !ok || time.Now().After(bo5xx.BackoffUntil) {
		return 0, "", 0
	}

	return time.Until(bo5xx.BackoffUntil), fmt.Sprintf("Backoff until %s due to HTTP %d", bo5xx.BackoffUntil.Format(time.RFC1123), bo5xx.StatusCode), bo5xx.StatusCode
}

func (m *Monitor) Get4xxBackoff(submissionURL string) (time.Duration, string, int) {
	m.mutex4xx.RLock()
	defer m.mutex4xx.RUnlock()

	bo4xx, ok := m.backoff4xx[submissionURL]
	if !ok || time.Now().After(bo4xx.BackoffUntil) {
		return 0, "", 0
	}

	return time.Until(bo4xx.BackoffUntil), fmt.Sprintf("Backoff until %s due to HTTP %d", bo4xx.BackoffUntil.Format(time.RFC1123), bo4xx.StatusCode), bo4xx.StatusCode
}

func (m *Monitor) GetSlowResponseBackoff(submissionURL string) (time.Duration, string) {
	m.mutexSlowResponse.RLock()
	defer m.mutexSlowResponse.RUnlock()

	boSlow, ok := m.backoffSlowResponse[submissionURL]
	if !ok || time.Now().After(boSlow.BackoffUntil) {
		return 0, ""
	}

	return time.Until(boSlow.BackoffUntil), fmt.Sprint("Recent timeout/slow response backoff in effect (backoff until ", boSlow.BackoffUntil.Format(time.RFC1123), ")")
}

func parseRetryAfter(httpResponse *http.Response) time.Duration {
	retryAfter := httpResponse.Header.Get("Retry-After")
	if retryAfter == "" {
		return 0
	}

	// Try parsing as an integer (delay-seconds).
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}

	// Try parsing as an HTTP-date.
	if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}

	return 0
}
