package monitor

import (
	"net/http"
	"sync"

	"github.com/crtsh/ctsubmit/config"
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
// caches are pre-populated for all known logs in ctloglists.CrtshV3Active.
func New(cfg *config.Settings) *Monitor {
	m := &Monitor{
		cfg:                 cfg,
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
