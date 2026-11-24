# Runnel-Plugin "ldap". Ziele: make build | test | lint | fuzz | dist | runnel-test
GOLANGCI_LINT_VERSION := v2.15.0
# Ohne passendes golangci-lint im PATH: make lint GOLANGCI_LINT=bin/tools/golangci-lint
GOLANGCI_LINT ?= golangci-lint
FUZZTIME      ?= 30s
# Runnel für die Tests gegen den Host, z. B. RUNNEL_BIN=../runnel/bin/runnel
RUNNEL_BIN    ?=

.PHONY: build test lint fmt fuzz bench dist runnel-test clean

## build: Plugin für dieses System nach bin/ bauen
build:
	CGO_ENABLED=0 go build -trimpath -o bin/ldap$(shell go env GOEXE) .

## test: alle Tests mit Race-Detector (Tests mit LDAP-Server nur mit slapd, gegen Runnel nur mit RUNNEL_BIN)
test:
	RUNNEL_BIN=$(RUNNEL_BIN) go test -race ./...

## lint: golangci-lint für Linux- und Windows-Code
lint:
	$(GOLANGCI_LINT) run ./...
	GOOS=windows $(GOLANGCI_LINT) run ./...

## fmt: Quelltext formatieren
fmt:
	$(GOLANGCI_LINT) fmt ./...

## fuzz: Filter mit Platzhaltern und Zeitangaben mit zufälligen Eingaben
fuzz:
	go test -run '^$$' -fuzz FuzzFillFilter -fuzztime $(FUZZTIME) .
	go test -run '^$$' -fuzz FuzzParseTime -fuzztime $(FUZZTIME) .

## bench: Umwandeln von Einträgen in Datensätze
bench:
	go test -run '^$$' -bench . -benchmem .

## dist: Release-Archive und SHA256SUMS nach dist/
dist:
	scripts/dist.sh

## runnel-test: nur die Tests gegen Runnel (RUNNEL_BIN nötig)
runnel-test:
	@test -n "$(RUNNEL_BIN)" || (echo "set RUNNEL_BIN to the runnel program" && exit 2)
	RUNNEL_BIN=$(abspath $(RUNNEL_BIN)) go test -count=1 -run WithRunnel ./...

clean:
	rm -rf bin dist

bin/tools/golangci-lint:
	GOBIN=$(CURDIR)/bin/tools go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
