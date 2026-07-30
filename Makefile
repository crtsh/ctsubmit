all: clean generate ctsubmit

generate:
	go run github.com/valyala/quicktemplate/qtc@latest -dir=request/templates

ctsubmit:
	CGO_ENABLED=0 go build -o $@ -ldflags " \
	-X github.com/crtsh/ctsubmit/config.BuildTimestamp=`date --utc +%Y-%m-%dT%H:%M:%SZ` \
	-X github.com/crtsh/ctsubmit/config.CtsubmitVersion=`git describe --tags --always`"

clean:
	rm -f ctsubmit request/templates/*.qtpl.go
