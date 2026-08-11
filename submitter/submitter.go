package submitter

import (
	"context"
	"net/http"

	"github.com/crtsh/ctsubmit/config"
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/logger"

	"go.uber.org/zap"
)

// Submitter owns the dependencies used to submit certificates to CT logs.
// Construct one with New; the zero value is not usable.
type Submitter struct {
	cfg    *config.Settings
	log    *zap.Logger
	client *http.Client
}

// New returns a Submitter that submits over its own HTTP client, whose timeout
// is taken from cfg.
func New(cfg *config.Settings, log *zap.Logger) *Submitter {
	return &Submitter{
		cfg:    cfg,
		log:    log,
		client: &http.Client{Timeout: cfg.Strategy.Submission.HTTPTimeout},
	}
}

// std is the process-wide default Submitter backing the package-level Handler
// shim, so existing callers can migrate to New/Handle incrementally.
var std = New(&config.Config, logger.Logger)

// Handler submits using the default Submitter. Prefer constructing a Submitter
// with New and calling Handle.
func Handler(ctx context.Context, apiEndpoint endpoint.Endpoint, submissionRequest *SubmissionRequest) (*SubmissionResponse, error) {
	return std.Handle(ctx, apiEndpoint, submissionRequest)
}
