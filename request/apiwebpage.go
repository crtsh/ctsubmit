package request

import (
	"github.com/crtsh/ctsubmit/endpoint"
	"github.com/crtsh/ctsubmit/logger"
	"github.com/crtsh/ctsubmit/request/templates"

	"github.com/valyala/fasthttp"

	"go.uber.org/zap"
)

func APIWebpage(fhctx *fasthttp.RequestCtx, endpointPath string) {
	inputType := ""
	firstItem := ""
	switch endpointPath {
	case endpoint.ENDPOINTSTRING_ADDCHAIN:
		inputType = "Certificate"
		firstItem = "leaf"
	case endpoint.ENDPOINTSTRING_ADDPRECHAIN:
		inputType = "Precertificate"
		firstItem = "precertificate"
	}

	logger.SetDetails(fhctx, zap.InfoLevel, endpointPath+" webpage", nil, nil)
	fhctx.SetContentType("text/html")
	fhctx.SetStatusCode(fasthttp.StatusOK)
	templates.WriteAPIWebpage(fhctx, endpointPath, inputType, firstItem)
}
