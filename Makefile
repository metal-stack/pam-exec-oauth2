.ONESHELL:

SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))


GO111MODULE := on

.PHONY: all
all:
	CGO_ENABLED=0 \
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "-w -extldflags '-static' \
				-X 'github.com/metal-stack/v.Version=$(VERSION)' \
				-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				-X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
	-o bin/pam-exec-oauth2 .
	strip bin/pam-exec-oauth2

.PHONY: clean
clean:
	rm -rf bin/*
