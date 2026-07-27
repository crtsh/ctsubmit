package config

import (
	"math"
	"os"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/crtsh/ctsubmit/logger"

	"github.com/spf13/viper"

	"go.uber.org/zap"
)

type config struct {
	Server struct {
		WebserverPort        int           `mapstructure:"webserverPort"`
		WebserverPath        string        `mapstructure:"webserverPath"`
		MonitoringPort       int           `mapstructure:"monitoringPort"`
		MonitoringAddress    string        `mapstructure:"monitoringAddress"`
		MonitoringPath       string        `mapstructure:"monitoringPath"`
		EnableDebugEndpoints bool          `mapstructure:"enableDebugEndpoints"`
		SocketPermissions    os.FileMode   `mapstructure:"socketPermissions"`
		ReadTimeout          time.Duration `mapstructure:"readTimeout"`
		IdleTimeout          time.Duration `mapstructure:"idleTimeout"`
		DisableKeepalive     bool          `mapstructure:"disableKeepalive"`
		RequestTimeout       time.Duration `mapstructure:"requestTimeout"`
		LivezTimeout         time.Duration `mapstructure:"livezTimeout"`
		ReadyzTimeout        time.Duration `mapstructure:"readyzTimeout"`
		RememberBusyTimeout  time.Duration `mapstructure:"rememberBusyTimeout"`
		MetricsTimeout       time.Duration `mapstructure:"metricsTimeout"`
	}
	Strategy struct {
		Excluded struct {
			Operators   []string `mapstructure:"operators"`
			LogURLRegex []string `mapstructure:"logURLRegex"`
		}
		Preferred struct {
			Operators   []string `mapstructure:"operators"`
			LogURLRegex []string `mapstructure:"logURLRegex"`
		}
		UptimeThreshold struct {
			SubmitEndpoint24h float64 `mapstructure:"submitEndpoint24h"`
			LowestEndpoint90d float64 `mapstructure:"lowestEndpoint90d"`
		}
		Backoff struct {
			BadResponsePeriod  time.Duration `mapstructure:"badResponsePeriod"`
			TimeoutPeriod      time.Duration `mapstructure:"timeoutPeriod"`
			Default5xxPeriod   time.Duration `mapstructure:"default5xxPeriod"`
			Default4xxPeriod   time.Duration `mapstructure:"default4xxPeriod"`
			SlowResponsePeriod time.Duration `mapstructure:"slowResponsePeriod"`
		}
		Submission struct {
			TryNextResponseThreshold time.Duration `mapstructure:"tryNextResponseThreshold"`
			SlowResponseThreshold    time.Duration `mapstructure:"slowResponseThreshold"`
			HTTPTimeout              time.Duration `mapstructure:"httpTimeout"`
		}
	}
	STHMonitor struct {
		RefreshInterval time.Duration `mapstructure:"refreshInterval"`
		HTTPTimeout     time.Duration `mapstructure:"httpTimeout"`
	}
	UptimeFetcher struct {
		RefreshInterval time.Duration `mapstructure:"refreshInterval"`
		HTTPTimeout     time.Duration `mapstructure:"httpTimeout"`
	}
	Response struct {
		DefaultFormat       string `mapstructure:"defaultFormat"`
		JsonPrettyPrint     bool   `mapstructure:"jsonPrettyPrint"`
		IncludeLogResponses bool   `mapstructure:"includeLogResponses"`
		IncludeSCTList      bool   `mapstructure:"includeSCTList"`
		ProduceFinalTBSCert bool   `mapstructure:"produceFinalTBSCert"`
	}
	Logging struct {
		IsDevelopment        bool   `mapstructure:"isDevelopment"`
		Level                string `mapstructure:"level"`
		SamplingInitial      int    `mapstructure:"samplingInitial"`
		SamplingThereafter   int    `mapstructure:"samplingThereafter"`
		XFFUseFirstIPAddress bool   `mapstructure:"xffUseFirstIPAddress"`
	}
}

type ResponseFormat int

const (
	RESPONSEFORMAT_HTML ResponseFormat = iota
	RESPONSEFORMAT_JSON
)

var (
	ApplicationName       string
	ApplicationNamespace  string
	Config                config
	DefaultResponseFormat = RESPONSEFORMAT_JSON

	// Automatically populated by the build system (see Makefile / Dockerfile).
	BuildTimestamp                              string
	Vcs, VcsModified, VcsRevision, VcsTimestamp string
	CtsubmitVersion                             string
)

func init() {
	// Determine the application name and namespace.
	if path, err := os.Executable(); err != nil {
		panic(err)
	} else {
		ApplicationName = path[strings.LastIndex(path, "/")+1:]
		ApplicationNamespace = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(ApplicationName, "-", ""), "_", ""))
	}

	// Initialize Viper and Logger.
	if err := initViper(); err != nil {
		panic(err)
	} else if err = logger.InitLogger(Config.Logging.IsDevelopment, Config.Logging.Level, Config.Logging.SamplingInitial, Config.Logging.SamplingThereafter); err != nil {
		panic(err)
	}
	logger.XFFUseFirstIPAddress = Config.Logging.XFFUseFirstIPAddress

	// Validation configuration values.
	if Config.Strategy.UptimeThreshold.SubmitEndpoint24h < 0 || Config.Strategy.UptimeThreshold.SubmitEndpoint24h > 100 {
		logger.Logger.Fatal("strategy.uptimeThreshold.submitEndpoint24h must be between 0 and 100")
	}
	if Config.Strategy.UptimeThreshold.LowestEndpoint90d < 99 || Config.Strategy.UptimeThreshold.LowestEndpoint90d > 100 {
		logger.Logger.Fatal("strategy.uptimeThreshold.lowestEndpoint90d must be between 99 and 100")
	}
	if Config.Strategy.Backoff.BadResponsePeriod < 0 {
		logger.Logger.Fatal("strategy.backoff.badResponsePeriod must be non-negative")
	}
	if Config.Strategy.Backoff.TimeoutPeriod < 0 {
		logger.Logger.Fatal("strategy.backoff.timeoutPeriod must be non-negative")
	}
	if Config.Strategy.Backoff.Default5xxPeriod < 0 {
		logger.Logger.Fatal("strategy.backoff.default5xxPeriod must be non-negative")
	}
	if Config.Strategy.Backoff.Default4xxPeriod < 0 {
		logger.Logger.Fatal("strategy.backoff.default4xxPeriod must be non-negative")
	}
	if Config.Strategy.Backoff.SlowResponsePeriod < 0 {
		logger.Logger.Fatal("strategy.backoff.slowResponsePeriod must be non-negative")
	}
	if Config.Strategy.Submission.TryNextResponseThreshold <= 0 {
		logger.Logger.Fatal("strategy.submission.tryNextResponseThreshold must be positive")
	}
	if Config.Strategy.Submission.SlowResponseThreshold <= 0 {
		logger.Logger.Fatal("strategy.submission.slowResponseThreshold must be positive")
	}
	if Config.Strategy.Submission.HTTPTimeout <= 0 {
		logger.Logger.Fatal("strategy.submission.httpTimeout must be positive")
	}
	if Config.STHMonitor.RefreshInterval <= 0 {
		logger.Logger.Fatal("sthMonitor.refreshInterval must be positive")
	}
	if Config.STHMonitor.HTTPTimeout <= 0 {
		logger.Logger.Fatal("sthMonitor.httpTimeout must be positive")
	}
	if Config.UptimeFetcher.RefreshInterval <= 0 {
		logger.Logger.Fatal("uptimeFetcher.refreshInterval must be positive")
	}
	if Config.UptimeFetcher.HTTPTimeout <= 0 {
		logger.Logger.Fatal("uptimeFetcher.httpTimeout must be positive")
	}
	if !Config.Response.IncludeLogResponses && !Config.Response.IncludeSCTList && !Config.Response.ProduceFinalTBSCert {
		logger.Logger.Fatal("at least one of response.includeLogResponses, response.includeSCTList, response.produceFinalTBSCert must be true")
	}

	// Log build information.
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, bs := range bi.Settings {
			switch bs.Key {
			case "vcs":
				Vcs = bs.Value
			case "vcs.modified":
				VcsModified = bs.Value
			case "vcs.revision":
				VcsRevision = bs.Value
			case "vcs.time":
				VcsTimestamp = bs.Value
			}
		}
		logger.Logger.Info("Build information", zap.String("build_timestamp", BuildTimestamp), zap.String("vcs", Vcs), zap.String("vcs_modified", VcsModified), zap.String("vcs_revision", VcsRevision), zap.String("vcs_timestamp", VcsTimestamp))
	}

	if CtsubmitVersion == "" {
		CtsubmitVersion = VcsRevision
	}

	// Log RLIMIT_NOFILE soft and hard limits.
	var rlimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlimit); err != nil {
		logger.Logger.Error("Getrlimit(RLIMIT_NOFILE) error", zap.Error(err))
	} else {
		logger.Logger.Info("Resource limits", zap.Uint64("rlimit_nofile_soft", rlimit.Cur), zap.Uint64("rlimit_nofile_hard", rlimit.Max), zap.String("gomemlimit", os.Getenv("GOMEMLIMIT")))
	}
}

func initViper() error {
	// Imports config file values from least to most specific.
	viper.SetConfigName("config.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("/config")  // /config/config.yaml
	viper.AddConfigPath("./config") // ./config/config.yaml
	viper.AddConfigPath(".")        // ./config.yaml

	// Setup Viper to also look at environment variables.
	viper.SetEnvPrefix(ApplicationNamespace)
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // fix for nested struct references https://github.com/spf13/viper/issues/160#issuecomment-189551355
	viper.AutomaticEnv()

	// Enable environment variables to be unmarshalled to slices (https://stackoverflow.com/a/43241844).
	viper.SetTypeByDefaultValue(true)

	// Set defaults for all values in-order to use env config for all options.
	viper.SetDefault("server.webserverPort", 8080)
	viper.SetDefault("server.monitoringPort", 8081)
	viper.SetDefault("server.monitoringAddress", "")
	viper.SetDefault("server.enableDebugEndpoints", false)
	viper.SetDefault("server.socketPermissions", 0o600)
	viper.SetDefault("server.readTimeout", 30*time.Second)
	viper.SetDefault("server.idleTimeout", 30*time.Second)
	viper.SetDefault("server.disableKeepalive", false)
	viper.SetDefault("server.requestTimeout", 30*time.Second)
	viper.SetDefault("server.livezTimeout", 500*time.Millisecond)
	viper.SetDefault("server.readyzTimeout", 500*time.Millisecond)
	viper.SetDefault("server.rememberBusyTimeout", 5*time.Second)
	viper.SetDefault("server.metricsTimeout", 8*time.Second)
	viper.SetDefault("strategy.excluded.operators", []string{})
	viper.SetDefault("strategy.excluded.logURLRegex", []string{})
	viper.SetDefault("strategy.preferred.operators", []string{})
	viper.SetDefault("strategy.preferred.logURLRegex", []string{})
	viper.SetDefault("strategy.backoff.badResponsePeriod", time.Minute)
	viper.SetDefault("strategy.backoff.timeoutPeriod", time.Minute)
	viper.SetDefault("strategy.backoff.default5xxPeriod", time.Minute)
	viper.SetDefault("strategy.backoff.default4xxPeriod", time.Minute)
	viper.SetDefault("strategy.backoff.slowResponsePeriod", time.Minute)
	viper.SetDefault("strategy.uptimeThreshold.submitEndpoint24h", 95)
	viper.SetDefault("strategy.uptimeThreshold.lowestEndpoint90d", 99.25)
	viper.SetDefault("strategy.submission.tryNextResponseThreshold", 500*time.Millisecond)
	viper.SetDefault("strategy.submission.slowResponseThreshold", 2*time.Second)
	viper.SetDefault("strategy.submission.httpTimeout", 15*time.Second)
	viper.SetDefault("sthMonitor.refreshInterval", 30*time.Second)
	viper.SetDefault("sthMonitor.httpTimeout", 15*time.Second)
	viper.SetDefault("uptimeFetcher.refreshInterval", 30*time.Minute)
	viper.SetDefault("uptimeFetcher.httpTimeout", 15*time.Second)
	viper.SetDefault("response.includeLogResponses", true)
	viper.SetDefault("response.includeSCTList", false)
	viper.SetDefault("response.produceFinalTBSCert", false)
	viper.SetDefault("logging.isDevelopment", false)
	viper.SetDefault("logging.level", "")
	viper.SetDefault("logging.samplingInitial", math.MaxInt)    // When both of these are set to MaxInt, sampling is disabled.
	viper.SetDefault("logging.samplingThereafter", math.MaxInt) // See https://pkg.go.dev/go.uber.org/zap/zapcore#NewSamplerWithOptions for more information.
	viper.SetDefault("logging.xffUseFirstIPAddress", false)

	// Render results to Config Struct.
	_ = viper.ReadInConfig() // Ignore errors, because we also support reading config from environment variables.
	return viper.Unmarshal(&Config)
}

func ParseResponseFormat(format string) ResponseFormat {
	switch strings.ToLower(format) {
	case "html":
		return RESPONSEFORMAT_HTML
	case "json":
		return RESPONSEFORMAT_JSON
	default:
		return -1
	}
}
