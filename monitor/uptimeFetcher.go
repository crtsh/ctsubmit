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

func (m *Monitor) initUptimeMaps() {
	initializeUptimeMap(m.uptime24h)
	initializeUptimeMap(m.uptime90d)
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

func (m *Monitor) UptimeFetcher(ctx context.Context) {
	m.log.Info("Started UptimeFetcher")

	for {
		select {
		// Fetch endpoint uptime information from Google's log monitoring, then fire a timer when it's time to re-fetch.
		case <-time.After(m.cfg.UptimeFetcher.RefreshInterval):
			m.FetchEndpointUptimes()
		// Respond to graceful shutdown requests.
		case <-ctx.Done():
			logger.ShutdownWG.Done()
			m.log.Info("Stopped UptimeFetcher")
			return
		}
	}
}

func (m *Monitor) FetchEndpointUptimes() {
	var err error

	if err = m.fetchEndpointUptimes(endpointUptime24hURL, m.uptime24h, &m.mutex24h); err != nil {
		m.log.Warn("Failed to fetch 24h endpoint uptime", zap.Error(err))
	}

	if err = m.fetchEndpointUptimes(endpointUptime90dURL, m.uptime90d, &m.mutex90d); err != nil {
		m.log.Warn("Failed to fetch 90d endpoint uptime", zap.Error(err))
	}
}

func (m *Monitor) fetchEndpointUptimes(csvURL string, uptimeMap map[string]*EndpointUptimes, mutex *sync.RWMutex) error {
	req, err := http.NewRequest(http.MethodGet, csvURL, nil)
	if err != nil {
		return err
	}

	resp, err := m.uptimeHTTPClient.Do(req)
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
				m.log.Warn("Failed to parse endpoint uptime percentage", zap.String("url", line[0]), zap.String("endpoint", line[1]), zap.String("percentage", line[2]), zap.Error(err))
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
					m.log.Warn("Unknown endpoint in uptime data", zap.String("url", line[0]), zap.String("endpoint", line[1]), zap.String("percentage", line[2]))
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

func (m *Monitor) GetEndpointUptime24h(submissionURL, endpoint string) (float64, bool) {
	m.mutex24h.RLock()
	defer m.mutex24h.RUnlock()
	return getEndpointUptime(m.uptime24h[submissionURL], endpoint)
}

func (m *Monitor) GetEndpointUptime90d(submissionURL, endpoint string) (float64, bool) {
	m.mutex90d.RLock()
	defer m.mutex90d.RUnlock()
	return getEndpointUptime(m.uptime90d[submissionURL], endpoint)
}
