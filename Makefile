.ONESHELL:
CGO_ENABLED := $(or ${CGO_ENABLED},0)
GO := go
GO111MODULE := on

.PHONY: all
all:
	$(GO) build -o bin/pam-exec-oauth2 .
	strip bin/pam-exec-oauth2

.PHONY: clean
clean:
	rm -rf bin/*
