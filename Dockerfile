# Install tini in a stage pinned to the target platform so apk fetches the
# native binary for that arch (apk does not cross-compile).
FROM --platform=$TARGETPLATFORM docker.io/library/golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS tini
RUN apk add --no-cache tini-static

FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27.1-alpine3.24@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG gomodfile=go.mod
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH
RUN apk add --no-cache git
WORKDIR /build
COPY . .
RUN go run github.com/valyala/quicktemplate/qtc@v1.8.0 -dir=request/templates \
&& go build -modfile=$gomodfile -o ctsubmit -ldflags " \
-X github.com/crtsh/ctsubmit/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
-X github.com/crtsh/ctsubmit/config.CtsubmitVersion=`git describe --tags --always`" /build/.

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /build/ctsubmit /app/ctsubmit
COPY --from=tini --chown=nonroot:nonroot /sbin/tini-static /sbin/tini
VOLUME ["/config"]
ENTRYPOINT [ "/sbin/tini", "--", "/app/ctsubmit" ]

LABEL \
    org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot" \
    org.opencontainers.image.title="ctsubmit" \
    org.opencontainers.image.source="https://github.com/crtsh/ctsubmit"
