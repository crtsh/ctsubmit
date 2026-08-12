package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/logger"
)

func TestGetEndpointUptime(t *testing.T) {
	eu := &EndpointUptimes{
		Lowest:            1,
		AddChain:          2,
		AddPreChain:       3,
		GetEntries:        4,
		GetProofByHash:    5,
		GetRoots:          6,
		GetSTH:            7,
		GetSTHConsistency: 8,
		Checkpoint:        9,
		Tile:              10,
	}
	cases := map[string]float64{
		"LOWEST":              1,
		"add-chain":           2,
		"add-pre-chain":       3,
		"get-entries":         4,
		"get-proof-by-hash":   5,
		"get-roots":           6,
		"get-sth":             7,
		"get-sth-consistency": 8,
		"checkpoint":          9,
		"tile":                10,
	}
	for ep, want := range cases {
		if got, ok := getEndpointUptime(eu, ep); !ok || got != want {
			t.Errorf("getEndpointUptime(%q): got (%v, %v), want (%v, true)", ep, got, ok, want)
		}
	}
	if _, ok := getEndpointUptime(nil, "LOWEST"); ok {
		t.Error("nil uptimes should return ok=false")
	}
	if _, ok := getEndpointUptime(eu, "unknown-endpoint"); ok {
		t.Error("unknown endpoint should return ok=false")
	}

	m := New(config.MustLoad())
	m.uptime24h["https://uptime.example/"] = eu
	m.uptime90d["https://uptime.example/"] = eu
	if got, ok := m.GetEndpointUptime24h("https://uptime.example/", "add-chain"); !ok || got != 2 {
		t.Errorf("GetEndpointUptime24h: got (%v, %v), want (2, true)", got, ok)
	}
	if got, ok := m.GetEndpointUptime90d("https://uptime.example/", "LOWEST"); !ok || got != 1 {
		t.Errorf("GetEndpointUptime90d: got (%v, %v), want (1, true)", got, ok)
	}
}

func TestFetchResource(t *testing.T) {
	m := New(config.MustLoad())
	const url = "https://fetch-resource.example/"

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	defer ok.Close()
	if body := m.fetchResource(url, ok.URL); string(body) != "hello" {
		t.Errorf("fetchResource(200): got %q, want %q", body, "hello")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if body := m.fetchResource(url, notFound.URL); body != nil {
		t.Errorf("fetchResource(404): got %q, want nil", body)
	}

	serverErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer serverErr.Close()
	if body := m.fetchResource(url, serverErr.URL); body != nil {
		t.Errorf("fetchResource(500): got %q, want nil", body)
	}

	// A closed server yields a connection error.
	down := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	downURL := down.URL
	down.Close()
	if body := m.fetchResource(url, downURL); body != nil {
		t.Errorf("fetchResource(conn error): got %q, want nil", body)
	}
}

func TestFetchEndpointUptimes(t *testing.T) {
	m := New(config.MustLoad())

	// Pick a real log URL that initializeUptimeMap knows about, so the parsed row
	// is retained.
	var known string
	for k := range m.uptime24h {
		known = k
		break
	}
	if known == "" {
		t.Skip("no known log URLs to test with")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("url,endpoint,percentage\n" + known + ",add-chain,99.5\n"))
	}))
	defer srv.Close()

	if err := m.fetchEndpointUptimes(srv.URL, m.uptime24h, &m.mutex24h); err != nil {
		t.Fatalf("fetchEndpointUptimes: %v", err)
	}
	if got, ok := m.GetEndpointUptime24h(known, "add-chain"); !ok || got != 99.5 {
		t.Errorf("after fetch: got (%v, %v), want (99.5, true)", got, ok)
	}

	// A non-200 response surfaces as an error.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer bad.Close()
	if err := m.fetchEndpointUptimes(bad.URL, m.uptime24h, &m.mutex24h); err == nil {
		t.Error("expected an error for a non-200 uptime response")
	}
}

func TestMonitorLoopsStopOnContextCancel(t *testing.T) {
	m := New(config.MustLoad())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done, so each loop takes the ctx.Done() path immediately.

	logger.ShutdownWG.Add(2)
	m.STHMonitor(ctx)
	m.UptimeFetcher(ctx)
}
