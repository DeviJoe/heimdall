.PHONY: check test test-unit test-regression test-regression-db test-regression-ui test-regression-api test-regression-freebsd test-load test-integration test-e2e test-all demo verify proto dashboards agent-freebsd
check: test-unit
test: test-unit
test-unit:
	sh scripts/test.sh unit
test-regression:
	sh scripts/test.sh regression
test-regression-ui:
	sh scripts/test.sh ui
test-regression-db:
	sh scripts/test.sh integration
test-regression-api:
	sh scripts/test.sh e2e
test-regression-freebsd:
	python3 scripts/check-freebsd.py
test-load:
	sh scripts/test.sh load
test-integration: test-regression-db
test-e2e: test-regression-api
test-all:
	sh scripts/test.sh all
dashboards:
	python3 scripts/generate-dashboards.py
demo:
	sh scripts/demo.sh
verify: test-regression-api
agent-freebsd:
	mkdir -p .local/freebsd
	GOOS=freebsd GOARCH=$${ARCH:-amd64} CGO_ENABLED=0 go build -trimpath -o .local/freebsd/heimdall-agent ./cmd/heimdall-agent
proto:
	PATH="$(shell go env GOPATH)/bin:$$PATH" protoc --go_out=. --go_opt=module=Heimdall --go-grpc_out=. --go-grpc_opt=module=Heimdall api/proto/linpam/agent/v1/agent.proto
