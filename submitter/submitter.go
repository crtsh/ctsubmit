package submitter

import (
	"net/http"
	"regexp"

	"github.com/crtsh/ctsubmit/config"

	"go.uber.org/zap"
)

// Submitter owns the dependencies used to submit certificates to CT logs.
// Construct one with New; the zero value is not usable.
type Submitter struct {
	cfg                 *config.Settings
	log                 *zap.Logger
	client              *http.Client
	excludedURLRegexes  []*regexp.Regexp
	preferredURLRegexes []*regexp.Regexp
}

// New returns a Submitter that submits over its own HTTP client, whose timeout
// is taken from cfg.
func New(cfg *config.Settings, log *zap.Logger) *Submitter {
	return &Submitter{
		cfg:                 cfg,
		log:                 log,
		client:              &http.Client{Timeout: cfg.Strategy.Submission.HTTPTimeout},
		excludedURLRegexes:  compileRegexes(cfg.Strategy.Excluded.LogURLRegex),
		preferredURLRegexes: compileRegexes(cfg.Strategy.Preferred.LogURLRegex),
	}
}
