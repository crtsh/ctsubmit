package request

import (
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/request/templates"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func FrontPage(fhctx *fasthttp.RequestCtx) {
	logger.SetDetails(fhctx, zap.InfoLevel, "Front page", nil, nil)
	fhctx.SetContentType("text/html")
	fhctx.SetStatusCode(fasthttp.StatusOK)
	templates.WriteFrontPage(fhctx)
}
