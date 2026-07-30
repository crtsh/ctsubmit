FROM docker.io/library/golang:1.26.5-alpine AS builder
ARG gomodfile=go.mod
ENV CGO_ENABLED=0 \
    GOARCH=amd64
RUN apk add --no-cache git tini-static
WORKDIR /build
COPY . .
RUN go run github.com/valyala/quicktemplate/qtc@latest -dir=request/templates \
&& go build -modfile=$gomodfile -o ctsubmit -ldflags " \
-X github.com/crtsh/ctsubmit/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
-X github.com/crtsh/ctsubmit/config.CtsubmitVersion=`git describe --tags --always`" /build/.

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
COPY --from=builder --chown=nonroot:nonroot /build/ctsubmit /app/ctsubmit
COPY --from=builder --chown=nonroot:nonroot /sbin/tini-static /sbin/tini
VOLUME ["/config"]
ENTRYPOINT [ "/sbin/tini", "--", "/app/ctsubmit" ]

LABEL \
    org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot" \
    org.opencontainers.image.title="ctsubmit" \
    org.opencontainers.image.source="https://github.com/crtsh/ctsubmit"
