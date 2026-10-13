# Builds fully static gk-fltr binaries with zig as the C (cross) compiler.
#
#   make ndpi            build third_party/ndpi/<arch>/lib/libndpi.a
#   make                 build bin/gk-fltr-amd64 and bin/gk-fltr-arm64
#   make test            run the tests (amd64 host)

ARCHS     ?= amd64 arm64
zigtarget  = $(if $(filter amd64,$(1)),x86_64-linux-musl,aarch64-linux-musl)
LDFLAGS    = -s -w -linkmode=external "-extldflags=-static -s"

.PHONY: all ndpi test clean $(ARCHS:%=bin/gk-fltr-%)

all: $(ARCHS:%=bin/gk-fltr-%)

ndpi:
	scripts/build-ndpi.sh $(ARCHS)

$(ARCHS:%=bin/gk-fltr-%): bin/gk-fltr-%:
	CGO_ENABLED=1 GOOS=linux GOARCH=$* CC="zig cc -target $(call zigtarget,$*)" \
		go build -trimpath -ldflags '$(LDFLAGS)' -o $@ .

test:
	CGO_ENABLED=1 CC="zig cc -target x86_64-linux-musl" go test -ldflags '$(LDFLAGS)' ./...

clean:
	rm -rf bin third_party/ndpi
