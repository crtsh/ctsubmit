package monitor

import (
	"context"
	"encoding/csv"
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

const (
	endpointUptime24hURL = "https://www.gstatic.com/ct/compliance/endpoint_uptime_24h.csv"
	endpointUptime90dURL = "https://www.gstatic.com/ct/compliance/endpoint_uptime.csv"
)

type EndpointUptimes struct {
	Lowest            float64
	AddChain          float64
	AddPreChain       float64
	GetEntries        float64
	GetProofByHash    float64
	GetRoots          float64
	GetSTH            float64
	GetSTHConsistency float64
	Checkpoint        float64
	Tile              float64
}

var (
	uptime24h = make(map[string]*EndpointUptimes)
	mutex24h  sync.RWMutex
	uptime90d = make(map[string]*EndpointUptimes)
	mutex90d  sync.RWMutex
	// Built lazily so importing this package does not read config at init time.
	uptimeHTTPClient = sync.OnceValue(func() *http.Client {
		return &http.Client{Timeout: config.Config.UptimeFetcher.HTTPTimeout}
	})
)

func init() {
	initializeUptimeMap(uptime24h)
	initializeUptimeMap(uptime90d)
}

func initializeUptimeMap(uptimeMap map[string]*EndpointUptimes) {
	for _, operator := range ctloglists.CrtshV3Active.Operators {
		for _, log := range operator.Logs {
			submissionURL, _ := url.JoinPath(log.URL, "/")
			uptimeMap[submissionURL] = nil
		}
		for _, tiledLog := range operator.TiledLogs {
			submissionURL, _ := url.JoinPath(tiledLog.SubmissionURL, "/")
			uptimeMap[submissionURL] = nil
		}
	}
}

func UptimeFetcher(ctx context.Context) {
	logger.Logger.Info("Started UptimeFetcher")

	for {
		select {
		// Fetch endpoint uptime information from Google's log monitoring, then fire a timer when it's time to re-fetch.
		case <-time.After(config.Config.UptimeFetcher.RefreshInterval):
			FetchEndpointUptimes()
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			logger.ShutdownWG.Done()
			logger.Logger.Info("Stopped UptimeFetcher")
			return
		}
	}
}

func FetchEndpointUptimes() {
	var err error

	if err = fetchEndpointUptimes(endpointUptime24hURL, uptime24h, &mutex24h); err != nil {
		logger.Logger.Warn("Failed to fetch 24h endpoint uptime", zap.Error(err))
	}

	if err = fetchEndpointUptimes(endpointUptime90dURL, uptime90d, &mutex90d); err != nil {
		logger.Logger.Warn("Failed to fetch 90d endpoint uptime", zap.Error(err))
	}
}

func fetchEndpointUptimes(csvURL string, uptimeMap map[string]*EndpointUptimes, mutex *sync.RWMutex) error {
	req, err := http.NewRequest(http.MethodGet, csvURL, nil)
	if err != nil {
		return err
	}

	resp, err := uptimeHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = 3
	reader.TrimLeadingSpace = true
	reader.ReuseRecord = true
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	mutex.Lock()
	defer mutex.Unlock()

	initializeUptimeMap(uptimeMap)

	for _, line := range records[1:] {
		endpointUptime, found := uptimeMap[line[0]]
		if found {
			if endpointUptime == nil {
				endpointUptime = &EndpointUptimes{Lowest: 100}
				uptimeMap[line[0]] = endpointUptime
			}
			percentage, err := strconv.ParseFloat(line[2], 64)
			if err != nil {
				logger.Logger.Warn("Failed to parse endpoint uptime percentage", zap.String("url", line[0]), zap.String("endpoint", line[1]), zap.String("percentage", line[2]), zap.Error(err))
			} else {
				switch line[1] {
				case "add-chain":
					endpointUptime.AddChain = percentage
				case "add-pre-chain":
					endpointUptime.AddPreChain = percentage
				case "get-entries":
					endpointUptime.GetEntries = percentage
				case "get-proof-by-hash":
					endpointUptime.GetProofByHash = percentage
				case "get-roots":
					endpointUptime.GetRoots = percentage
				case "get-sth":
					endpointUptime.GetSTH = percentage
				case "get-sth-consistency":
					endpointUptime.GetSTHConsistency = percentage
				case "checkpoint":
					endpointUptime.Checkpoint = percentage
				case "tile":
					endpointUptime.Tile = percentage
				default:
					logger.Logger.Warn("Unknown endpoint in uptime data", zap.String("url", line[0]), zap.String("endpoint", line[1]), zap.String("percentage", line[2]))
				}

				if percentage < endpointUptime.Lowest {
					endpointUptime.Lowest = percentage
				}
			}
		}
	}

	return nil
}

func getEndpointUptime(endpointUptimes *EndpointUptimes, endpoint string) (float64, bool) {
	if endpointUptimes == nil {
		return 0, false
	}

	switch endpoint {
	case "LOWEST":
		return endpointUptimes.Lowest, true
	case "add-chain":
		return endpointUptimes.AddChain, true
	case "add-pre-chain":
		return endpointUptimes.AddPreChain, true
	case "get-entries":
		return endpointUptimes.GetEntries, true
	case "get-proof-by-hash":
		return endpointUptimes.GetProofByHash, true
	case "get-roots":
		return endpointUptimes.GetRoots, true
	case "get-sth":
		return endpointUptimes.GetSTH, true
	case "get-sth-consistency":
		return endpointUptimes.GetSTHConsistency, true
	case "checkpoint":
		return endpointUptimes.Checkpoint, true
	case "tile":
		return endpointUptimes.Tile, true
	default:
		return 0, false
	}
}

func GetEndpointUptime24h(submissionURL, endpoint string) (float64, bool) {
	mutex24h.RLock()
	defer mutex24h.RUnlock()
	return getEndpointUptime(uptime24h[submissionURL], endpoint)
}

func GetEndpointUptime90d(submissionURL, endpoint string) (float64, bool) {
	mutex90d.RLock()
	defer mutex90d.RUnlock()
	return getEndpointUptime(uptime90d[submissionURL], endpoint)
}
