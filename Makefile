.ONESHELL:

SHA := $(shell git rev-parse --short=8 HEAD)
GITVERSION := $(shell git describe --long --all)
BUILDDATE := $(shell date -Iseconds)
VERSION := $(or ${GITHUB_TAG_NAME},$(shell git describe --tags --exact-match 2> /dev/null || git symbolic-ref -q --short HEAD || git rev-parse --short HEAD))

INSTALL = /usr/bin/install
INSTALL_PROGRAM = ${INSTALL} -m 755
INSTALL_DATA = ${INSTALL} -m 644

GO111MODULE := on

all: pam nss

.PHONY: pam
pam:
	CGO_ENABLED=0 \
	go build \
		-trimpath \
		-tags netgo \
		-ldflags "-w -extldflags '-static' \
				-X 'github.com/metal-stack/v.Version=$(VERSION)' \
				-X 'github.com/metal-stack/v.Revision=$(GITVERSION)' \
				-X 'github.com/metal-stack/v.GitSHA1=$(SHA)' \
				-X 'github.com/metal-stacj/v.BuildDate=$(BUILDDATE)'" \
	-o bin/pam-exec-oauth2 ./cmd/pam-exec-oauth2
	strip bin/pam-exec-oauth2

.PHONY: nss
nss:
	CGO_CFLAGS='-g -O2 -D __LIB_NSS_NAME=oauth2'  \
	go build --buildmode=c-shared -o bin/libnss_oauth2.so.2 ./cmd/nss-oauth2
	strip bin/libnss_oauth2.so.2

.PHONY: clean
clean:
	rm -rf bin/*

install: all
	${INSTALL_DATA} bin/libnss_oauth2.so.2 ${prefix}/lib/libnss_oauth2.so.2
	${INSTALL_PROGRAM} bin/pam-exec-oauth2 ${prefix}/sbin/pam-exec-oauth2
	${INSTALL_DATA} sample.yaml ${prefix}/etc/oauth2-login.conf
