FROM docker.io/library/golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS build
ARG gomodfile=go.mod
ENV CGO_ENABLED=0 \
    GOARCH=amd64
RUN apk add --no-cache git tini-static
WORKDIR /build
COPY . .
RUN go run github.com/valyala/quicktemplate/qtc@v1.8.0 -dir=request/templates \
&& go build -modfile=$gomodfile -o ctsubmit -ldflags " \
-X github.com/crtsh/ctsubmit/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
-X github.com/crtsh/ctsubmit/config.CtsubmitVersion=`git describe --tags --always`" /build/.

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /build/ctsubmit /app/ctsubmit
COPY --from=build --chown=nonroot:nonroot /sbin/tini-static /sbin/tini
VOLUME ["/config"]
ENTRYPOINT [ "/sbin/tini", "--", "/app/ctsubmit" ]

LABEL \
    org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot" \
    org.opencontainers.image.title="ctsubmit" \
    org.opencontainers.image.source="https://github.com/crtsh/ctsubmit"
