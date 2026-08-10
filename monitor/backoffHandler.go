package monitor

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"

	"github.com/crtsh/ctloglists"

	"go.uber.org/zap"
)

type backoffEntry struct {
	BackoffUntil  time.Time
	BackoffPeriod time.Duration
	StatusCode    int
}

var (
	backoffBadResponse  = make(map[string]*backoffEntry)
	mutexBadResponse    sync.RWMutex
	backoffTimeout      = make(map[string]*backoffEntry)
	mutexTimeout        sync.RWMutex
	backoff5xx          = make(map[string]*backoffEntry)
	mutex5xx            sync.RWMutex
	backoff4xx          = make(map[string]*backoffEntry)
	mutex4xx            sync.RWMutex
	backoffSlowResponse = make(map[string]*backoffEntry)
	mutexSlowResponse   sync.RWMutex
)

func init() {
	for _, operator := range ctloglists.CrtshV3Active.Operators {
		for _, log := range operator.Logs {
			submissionURL, _ := url.JoinPath(log.URL, "/")
			backoffBadResponse[submissionURL] = &backoffEntry{}
			backoffTimeout[submissionURL] = &backoffEntry{}
			backoff5xx[submissionURL] = &backoffEntry{}
			backoff4xx[submissionURL] = &backoffEntry{}
			backoffSlowResponse[submissionURL] = &backoffEntry{}
		}
		for _, tiledLog := range operator.TiledLogs {
			submissionURL, _ := url.JoinPath(tiledLog.SubmissionURL, "/")
			backoffBadResponse[submissionURL] = &backoffEntry{}
			backoffTimeout[submissionURL] = &backoffEntry{}
			backoff5xx[submissionURL] = &backoffEntry{}
			backoff4xx[submissionURL] = &backoffEntry{}
			backoffSlowResponse[submissionURL] = &backoffEntry{}
		}
	}
}

func RecordBadResponse(submissionURL string, err error) bool {
	logger.Logger.Warn("Bad response", zap.String("url", submissionURL), zap.Error(err))

	mutexBadResponse.Lock()
	defer mutexBadResponse.Unlock()

	boBad, ok := backoffBadResponse[submissionURL]
	if !ok {
		boBad = &backoffEntry{}
		backoffBadResponse[submissionURL] = boBad
	}

	backoffUntil := time.Now().Add(config.Config.Strategy.Backoff.BadResponsePeriod)
	if boBad.BackoffUntil.Before(backoffUntil) {
		boBad.BackoffUntil = backoffUntil
		boBad.BackoffPeriod = config.Config.Strategy.Backoff.BadResponsePeriod
	}

	return true
}

func RecordTimeout(submissionURL string, err error) bool {
	logger.Logger.Warn("Connection timeout", zap.String("url", submissionURL), zap.Error(err))

	mutexTimeout.Lock()
	defer mutexTimeout.Unlock()

	boTimeout, ok := backoffTimeout[submissionURL]
	if !ok {
		boTimeout = &backoffEntry{}
		backoffTimeout[submissionURL] = boTimeout
	}

	backoffUntil := time.Now().Add(config.Config.Strategy.Backoff.TimeoutPeriod)
	if boTimeout.BackoffUntil.Before(backoffUntil) {
		boTimeout.BackoffUntil = backoffUntil
		boTimeout.BackoffPeriod = config.Config.Strategy.Backoff.TimeoutPeriod
	}

	return true
}

func Record5xxResponse(submissionURL string, httpResponse *http.Response) bool {
	logger.Logger.Warn("HTTP server error", zap.Int("status_code", httpResponse.StatusCode), zap.String("url", submissionURL))

	backoffDuration := config.Config.Strategy.Backoff.Default5xxPeriod
	if retryAfter := parseRetryAfter(httpResponse); retryAfter > 0 {
		backoffDuration = retryAfter
	}

	mutex5xx.Lock()
	defer mutex5xx.Unlock()

	bo5xx, ok := backoff5xx[submissionURL]
	if !ok {
		bo5xx = &backoffEntry{}
		backoff5xx[submissionURL] = bo5xx
	}

	backoffUntil := time.Now().Add(backoffDuration)
	if bo5xx.BackoffUntil.Before(backoffUntil) {
		bo5xx.BackoffUntil = backoffUntil
		bo5xx.BackoffPeriod = backoffDuration
		bo5xx.StatusCode = httpResponse.StatusCode
	}

	return true
}

func Record4xxResponse(submissionURL string, httpResponse *http.Response) bool {
	logger.Logger.Warn("HTTP client error", zap.Int("status_code", httpResponse.StatusCode), zap.String("url", submissionURL))

	backoffDuration := config.Config.Strategy.Backoff.Default4xxPeriod
	if retryAfter := parseRetryAfter(httpResponse); retryAfter > 0 {
		backoffDuration = retryAfter
	}

	mutex4xx.Lock()
	defer mutex4xx.Unlock()

	bo4xx, ok := backoff4xx[submissionURL]
	if !ok {
		bo4xx = &backoffEntry{}
		backoff4xx[submissionURL] = bo4xx
	}

	backoffUntil := time.Now().Add(backoffDuration)
	if bo4xx.BackoffUntil.Before(backoffUntil) {
		bo4xx.BackoffUntil = backoffUntil
		bo4xx.BackoffPeriod = backoffDuration
		bo4xx.StatusCode = httpResponse.StatusCode
	}

	return true
}

func RecordSlowResponse(submissionURL string) bool {
	logger.Logger.Warn("Slow response", zap.String("url", submissionURL))

	mutexSlowResponse.Lock()
	defer mutexSlowResponse.Unlock()

	boSlow, ok := backoffSlowResponse[submissionURL]
	if !ok {
		boSlow = &backoffEntry{}
		backoffSlowResponse[submissionURL] = boSlow
	}

	backoffUntil := time.Now().Add(config.Config.Strategy.Backoff.SlowResponsePeriod)
	if boSlow.BackoffUntil.Before(backoffUntil) {
		boSlow.BackoffUntil = backoffUntil
		boSlow.BackoffPeriod = config.Config.Strategy.Backoff.SlowResponsePeriod
	}
	return true
}

func GetBadResponseBackoff(submissionURL string) (time.Duration, string) {
	mutexBadResponse.RLock()
	defer mutexBadResponse.RUnlock()

	boBad, ok := backoffBadResponse[submissionURL]
	if !ok || time.Now().After(boBad.BackoffUntil) {
		return 0, ""
	}

	return time.Until(boBad.BackoffUntil), fmt.Sprintf("Backoff until %s due to recent bad response", boBad.BackoffUntil.Format(time.RFC1123))
}

func GetTimeoutBackoff(submissionURL string) (time.Duration, string) {
	mutexTimeout.RLock()
	defer mutexTimeout.RUnlock()

	boTimeout, ok := backoffTimeout[submissionURL]
	if !ok || time.Now().After(boTimeout.BackoffUntil) {
		return 0, ""
	}

	return time.Until(boTimeout.BackoffUntil), fmt.Sprintf("Backoff until %s due to recent timeout", boTimeout.BackoffUntil.Format(time.RFC1123))
}

func Get5xxBackoff(submissionURL string) (time.Duration, string, int) {
	mutex5xx.RLock()
	defer mutex5xx.RUnlock()

	bo5xx, ok := backoff5xx[submissionURL]
	if !ok || time.Now().After(bo5xx.BackoffUntil) {
		return 0, "", 0
	}

	return time.Until(bo5xx.BackoffUntil), fmt.Sprintf("Backoff until %s due to HTTP %d", bo5xx.BackoffUntil.Format(time.RFC1123), bo5xx.StatusCode), bo5xx.StatusCode
}

func Get4xxBackoff(submissionURL string) (time.Duration, string, int) {
	mutex4xx.RLock()
	defer mutex4xx.RUnlock()

	bo4xx, ok := backoff4xx[submissionURL]
	if !ok || time.Now().After(bo4xx.BackoffUntil) {
		return 0, "", 0
	}

	return time.Until(bo4xx.BackoffUntil), fmt.Sprintf("Backoff until %s due to HTTP %d", bo4xx.BackoffUntil.Format(time.RFC1123), bo4xx.StatusCode), bo4xx.StatusCode
}

func GetSlowResponseBackoff(submissionURL string) (time.Duration, string) {
	mutexSlowResponse.RLock()
	defer mutexSlowResponse.RUnlock()

	boSlow, ok := backoffSlowResponse[submissionURL]
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
