package monitor

import (
	"net/http"
	"sync"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/loglists"

	"github.com/crtsh/ctloglists"
	"github.com/google/certificate-transparency-go/loglist3"

	"go.uber.org/zap"
)

// Monitor owns the runtime state used to track CT log health: backoff caches,
// STH/checkpoint data, endpoint uptime data, and sliding-window response
// samples. Construct one with New; the zero value is not usable.
//
// The Prometheus collectors remain package-level (registered once on the
// default registry), so constructing multiple Monitors (e.g. in tests) does not
// re-register them.
type Monitor struct {
	cfg *config.Settings
	lgr *zap.Logger

	backoffBadResponse  map[string]*backoffEntry
	mutexBadResponse    sync.RWMutex
	backoffTimeout      map[string]*backoffEntry
	mutexTimeout        sync.RWMutex
	backoff5xx          map[string]*backoffEntry
	mutex5xx            sync.RWMutex
	backoff4xx          map[string]*backoffEntry
	mutex4xx            sync.RWMutex
	backoffSlowResponse map[string]*backoffEntry
	mutexSlowResponse   sync.RWMutex

	sthData       map[string]*STHData
	sthMutex      sync.RWMutex
	sthHTTPClient *http.Client

	uptime24h        map[string]*EndpointUptimes
	mutex24h         sync.RWMutex
	uptime90d        map[string]*EndpointUptimes
	mutex90d         sync.RWMutex
	uptimeHTTPClient *http.Client

	outcomeSamples           map[string][]outcomeSample
	outcomeSamplesMutex      sync.Mutex
	responseTimeSamples      map[string][]responseTimeSample
	responseTimeSamplesMutex sync.Mutex
}

// New builds a Monitor whose HTTP client timeouts come from cfg and whose
// caches are pre-populated for all known logs in ctloglists.CrtshV3Active. The
// logger is optional; when omitted (e.g. in tests) a no-op logger is used.
func New(cfg *config.Settings, lgrs ...*zap.Logger) *Monitor {
	lgr := zap.NewNop()
	if len(lgrs) > 0 && lgrs[0] != nil {
		lgr = lgrs[0]
	}
	m := &Monitor{
		cfg:                 cfg,
		lgr:                 lgr,
		backoffBadResponse:  make(map[string]*backoffEntry),
		backoffTimeout:      make(map[string]*backoffEntry),
		backoff5xx:          make(map[string]*backoffEntry),
		backoff4xx:          make(map[string]*backoffEntry),
		backoffSlowResponse: make(map[string]*backoffEntry),
		sthData:             make(map[string]*STHData),
		uptime24h:           make(map[string]*EndpointUptimes),
		uptime90d:           make(map[string]*EndpointUptimes),
		outcomeSamples:      make(map[string][]outcomeSample),
		responseTimeSamples: make(map[string][]responseTimeSample),
		sthHTTPClient:       &http.Client{Timeout: cfg.STHMonitor.HTTPTimeout},
		uptimeHTTPClient:    &http.Client{Timeout: cfg.UptimeFetcher.HTTPTimeout},
	}
	m.initBackoffMaps()
	m.initSTHData()
	m.initUptimeMaps()
	return m
}

// monitoredLogLists returns the log lists whose logs need monitoring state.
func monitoredLogLists() []*loglist3.LogList {
	logLists := []*loglist3.LogList{ctloglists.CrtshV3Active}
	// A custom test log list (strategy.testLogListFilename) may contain logs that ctloglists knows nothing about.
	if customTestLogs := loglists.CustomTestLogList(); customTestLogs != nil {
		logLists = append(logLists, customTestLogs)
	}
	return logLists
}
