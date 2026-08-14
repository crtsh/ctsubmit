FROM docker.io/library/golang:1.26.6-alpine3.24@sha256:af8d6740070b8906d12eae1c3e3ea0957fb63f492051ea05e354c38ef9fe88df AS build
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

FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6
USER nonroot:nonroot
COPY --from=build --chown=nonroot:nonroot /build/ctsubmit /app/ctsubmit
COPY --from=build --chown=nonroot:nonroot /sbin/tini-static /sbin/tini
VOLUME ["/config"]
ENTRYPOINT [ "/sbin/tini", "--", "/app/ctsubmit" ]

LABEL \
    org.opencontainers.image.base.name="gcr.io/distroless/static:nonroot" \
    org.opencontainers.image.title="ctsubmit" \
    org.opencontainers.image.source="https://github.com/crtsh/ctsubmit"
