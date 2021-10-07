.ONESHELL:
GO := go
GO111MODULE := on

.PHONY: all
all:
	CGO_ENABLED=0 \
	$(GO) build \
		-trimpath \
		-tags netgo \
		-ldflags '-w -extldflags "-static"' \
	-o bin/pam-exec-oauth2 .
	strip bin/pam-exec-oauth2

.PHONY: clean
clean:
	rm -rf bin/*
