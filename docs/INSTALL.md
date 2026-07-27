# ctsubmit: Installation and Configuration

Contents:

- [Installation: Docker (Recommended method)](#installation-docker-recommended-method)
- [Installation: Manual](#installation-manual)
- [Architecture](#architecture)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Example `config.yaml`](#example-configyaml)
  - [Configuration Reference](#configuration-reference)
- [Monitoring Endpoints](#monitoring-endpoints)

## Installation: Docker (Recommended method)

Option 1: Use a [prebuilt ctsubmit container](https://github.com/orgs/crtsh/packages?repo_name=ctsubmit) from the GitHub Packages [Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

Option 2: Clone this repository and build the container yourself:

```bash
git clone https://github.com/crtsh/ctsubmit
docker build -t ctsubmit .
```

To run ctsubmit from the command-line, do this:

```bash
docker run -p 8080:8080 -p 8081:8081 -it ctsubmit
```

## Installation: Manual

Build the ctsubmit executable by running `make`:

```bash
git clone https://github.com/crtsh/ctsubmit
cd ctsubmit
make
```

Run the executable:

```bash
./ctsubmit
```

## Architecture

ctsubmit runs two HTTP servers:

| Server | Default Port | Purpose |
|---|---|---|
| Web | 8080 | REST API and web interface |
| Monitoring | 8081 | Health probes, Prometheus metrics, and debug endpoints |

The monitoring server binds to all interfaces by default. For hardened deployments, set `server.monitoringAddress` to `"127.0.0.1"` to restrict access to localhost only.

Both servers can alternatively listen on Unix sockets (see `server.webserverPath` and `server.monitoringPath` below).

## Configuration

ctsubmit uses [Viper](https://github.com/spf13/viper) to read configuration settings from environment variables and/or a `config.yaml` file.

Configuration files are searched for in the following locations (from least to most specific):

1. `/config/config.yaml`
2. `./config/config.yaml`
3. `./config.yaml`

For a full list of configuration options and their default values, please consult the [Configuration Reference](#configuration-reference).

### Environment Variables

Every configuration option can also be set via an environment variable. The environment variable name is derived from the YAML path by:

1. Uppercasing the entire path.
2. Replacing `.` with `_`.
3. Prefixing with `CTSUBMIT_`.

For example, `server.webserverPort` becomes `CTSUBMIT_SERVER_WEBSERVERPORT`.

```bash
docker run -p 9090:9090 -e CTSUBMIT_SERVER_WEBSERVERPORT=9090 -it ctsubmit
```

### Example `config.yaml`

```yaml
server:
  webserverPort: 8080           # Web API server port.
  monitoringPort: 8081          # Monitoring server port.
  monitoringAddress: ""         # Bind address for monitoring server ("127.0.0.1" for localhost only).
  enableDebugEndpoints: false   # Enable /debug/config and /debug/pprof/* endpoints.
  requestTimeout: 30s           # Maximum time to process a submission request.

strategy:
  excluded:
    operators: []               # Operator names to exclude from submissions.
    logURLRegex: []             # Log URL regexes to exclude from submissions.
  preferred:
    operators: []               # Operator names to prefer for submissions.
    logURLRegex: []             # Log URL regexes to prefer for submissions.
  uptimeThreshold:
    submitEndpoint24h: 95       # Minimum 24-hour uptime (%) for submit endpoint.
    lowestEndpoint90d: 99.25    # Minimum 90-day uptime (%) for any endpoint.
  backoff:
    badResponsePeriod: 1m       # Backoff after a bad (unparseable) response.
    timeoutPeriod: 1m           # Backoff after a connection timeout.
    default5xxPeriod: 1m        # Backoff after a 5xx error (unless Retry-After is set).
    default4xxPeriod: 1m        # Backoff after a 4xx error (unless Retry-After is set).
    slowResponsePeriod: 1m      # Backoff after a slow response.
  submission:
    tryNextResponseThreshold: 500ms  # Start submitting to the next log after this long.
    slowResponseThreshold: 2s        # Mark a response as "slow" after this long.
    httpTimeout: 15s                 # HTTP client timeout for log submissions.

sthMonitor:
  refreshInterval: 30s          # How often to fetch each log's latest STH/checkpoint.
  httpTimeout: 15s              # HTTP client timeout for STH fetches.

uptimeFetcher:
  refreshInterval: 30m          # How often to fetch endpoint uptime data.
  httpTimeout: 15s              # HTTP client timeout for uptime fetches.

response:
  defaultFormat: json           # Default response format: "json" or "html".
  jsonPrettyPrint: false        # Pretty-print JSON responses.

logging:
  isDevelopment: false          # Enable development mode logging.
  level: ""                     # Log level (debug, info, warn, error, dpanic, panic, fatal).
  xffUseFirstIPAddress: false   # Use first (not last) X-Forwarded-For IP for client_ip logging.
```

### Configuration Reference

#### Server

| Option | Default | Description |
|---|---|---|
| `server.webserverPort` | `8080` | Port for the web API server. |
| `server.webserverPath` | _(empty)_ | Unix socket path for the web server (overrides port). |
| `server.monitoringPort` | `8081` | Port for the monitoring server. |
| `server.monitoringAddress` | _(empty)_ | Bind address for the monitoring server. Empty or `"0.0.0.0"` listens on all interfaces. Set to `"127.0.0.1"` to restrict to localhost. |
| `server.monitoringPath` | _(empty)_ | Unix socket path for the monitoring server (overrides port). |
| `server.enableDebugEndpoints` | `false` | Enable `/debug/config` and `/debug/pprof/*` endpoints on the monitoring server. |
| `server.socketPermissions` | `0600` | Unix socket file permissions. |
| `server.readTimeout` | `30s` | HTTP read timeout. |
| `server.idleTimeout` | `30s` | HTTP idle connection timeout. |
| `server.disableKeepalive` | `false` | Disable HTTP keep-alive connections. |
| `server.requestTimeout` | `30s` | Maximum time to process a single submission request. |
| `server.livezTimeout` | `500ms` | Timeout for the `/livez` health probe handler. |
| `server.readyzTimeout` | `500ms` | Timeout for the `/readyz` readiness probe handler. |
| `server.rememberBusyTimeout` | `5s` | How long to remember a "busy" (timed out) state for readiness checks. |
| `server.metricsTimeout` | `8s` | Timeout for the `/metrics` handler. |

#### Strategy

| Option | Default | Description |
|---|---|---|
| `strategy.excluded.operators` | `[]` | Operator names to exclude from submissions. |
| `strategy.excluded.logURLRegex` | `[]` | Log URL regexes to exclude from submissions. |
| `strategy.preferred.operators` | `[]` | Operator names to prefer for submissions. |
| `strategy.preferred.logURLRegex` | `[]` | Log URL regexes to prefer for submissions. |
| `strategy.uptimeThreshold.submitEndpoint24h` | `95` | Minimum 24-hour uptime (%) for the submit endpoint before a log is dispreferred. |
| `strategy.uptimeThreshold.lowestEndpoint90d` | `99.25` | Minimum 90-day uptime (%) for any endpoint before a log is dispreferred. |
| `strategy.backoff.badResponsePeriod` | `1m` | Backoff duration after receiving a bad (unparseable) response. |
| `strategy.backoff.timeoutPeriod` | `1m` | Backoff duration after a connection timeout. |
| `strategy.backoff.default5xxPeriod` | `1m` | Default backoff after a 5xx error. Overridden by `Retry-After` header if present. |
| `strategy.backoff.default4xxPeriod` | `1m` | Default backoff after a 4xx error. Overridden by `Retry-After` header if present. |
| `strategy.backoff.slowResponsePeriod` | `1m` | Backoff duration after a slow response. |
| `strategy.submission.tryNextResponseThreshold` | `500ms` | Time to wait before speculatively starting a submission to the next log. |
| `strategy.submission.slowResponseThreshold` | `2s` | Time after which a response is recorded as "slow" for future dispreferal. |
| `strategy.submission.httpTimeout` | `15s` | HTTP client timeout for submissions to CT logs. |

#### STH Monitor

| Option | Default | Description |
|---|---|---|
| `sthMonitor.refreshInterval` | `30s` | How often to fetch each log's latest STH or checkpoint. |
| `sthMonitor.httpTimeout` | `15s` | HTTP client timeout for STH/checkpoint fetches. |

#### Uptime Fetcher

| Option | Default | Description |
|---|---|---|
| `uptimeFetcher.refreshInterval` | `30m` | How often to fetch endpoint uptime data from Google's compliance reports. |
| `uptimeFetcher.httpTimeout` | `15s` | HTTP client timeout for uptime data fetches. |

#### Response

| Option | Default | Description |
|---|---|---|
| `response.defaultFormat` | `json` | Default response format (`json` or `html`). |
| `response.jsonPrettyPrint` | `false` | Pretty-print JSON responses. |

#### Logging

| Option | Default | Description |
|---|---|---|
| `logging.isDevelopment` | `false` | Enable development mode logging (human-readable output). |
| `logging.level` | _(empty)_ | Log level: `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`. |
| `logging.samplingInitial` | `MaxInt` | Log sampling: number of initial messages to log per second. Disabled by default. |
| `logging.samplingThereafter` | `MaxInt` | Log sampling: log every Nth message after the initial burst. Disabled by default. |
| `logging.xffUseFirstIPAddress` | `false` | When `true`, use the first `X-Forwarded-For` entry (original client's claimed IP) for `client_ip` logging. When `false`, use the last entry (most likely added by a trusted proxy). |

## Monitoring Endpoints

The monitoring server (default port `8081`, all interfaces) exposes these endpoints:

| Endpoint | Description |
|---|---|
| `/livez` | Liveness probe. Returns HTTP 200 if the application has successfully processed at least one submission. |
| `/readyz` | Readiness probe. Returns HTTP 200 if the application is not in a "busy" (timed out) state. |
| `/metrics` | Prometheus metrics endpoint. |
| `/debug/build` | Go build information (module, dependencies, VCS details). Requires `server.enableDebugEndpoints: true`. |
| `/debug/config` | Current runtime configuration as formatted JSON. Requires `server.enableDebugEndpoints: true`. |
| `/debug/pprof/*` | Go pprof profiling endpoints. Requires `server.enableDebugEndpoints: true`. |

> **Security note:** The `/debug/*` endpoints are disabled by default. They can expose dependency versions, runtime configuration, and process internals. Enable them only in trusted environments. For production deployments where the monitoring port may be reachable from untrusted networks, keep `server.enableDebugEndpoints` set to `false` and consider setting `server.monitoringAddress` to `"127.0.0.1"`.

## Kubernetes Deployment

ctsubmit is designed for deployment in Kubernetes. Here is a minimal example:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ctsubmit
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ctsubmit
  template:
    metadata:
      labels:
        app: ctsubmit
    spec:
      containers:
        - name: ctsubmit
          image: ghcr.io/crtsh/ctsubmit:latest
          ports:
            - containerPort: 8080
              name: web
            - containerPort: 8081
              name: monitoring
          livenessProbe:
            httpGet:
              path: /livez
              port: monitoring
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: monitoring
            periodSeconds: 5
          volumeMounts:
            - name: config
              mountPath: /config
      volumes:
        - name: config
          configMap:
            name: ctsubmit-config
```
