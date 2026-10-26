#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mode=${1:-unit}
mkdir -p .local
prepare_database() {
 docker compose up -d postgres
 if ! docker compose exec -T postgres psql -U linpam -d postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$1'" | rg -q '^1$'; then
  docker compose exec -T postgres createdb -U linpam "$1"
 fi
}
case "$mode" in
 unit)
  # Build tags keep database and load fixtures out even when a DSN is exported.
  go test -race ./...
  go vet ./...
  npm --prefix web ci
  npm --prefix web run test:ci
  npm --prefix web run build
  ;;
 ui)
  npm --prefix web ci
  npm --prefix web run test:regression
  ;;
 integration)
  prepare_database linpam_test
  docker compose -f compose.yaml -f compose.test.yaml build tests
  docker compose -f compose.yaml -f compose.test.yaml run --rm tests
  ;;
 e2e)
  trap 'python3 -c "import runpy; runpy.run_path(\"scripts/check-demo.py\")[\"cleanup_admin_fixture\"]()"' EXIT
  python3 scripts/check-demo.py
  python3 scripts/check-recovery.py
  python3 scripts/check-features.py
  python3 scripts/check-enrollment.py
  ;;
 regression)
  sh scripts/test.sh ui
  sh scripts/test.sh integration
  sh scripts/demo.sh
  sh scripts/test.sh e2e
  ;;
 load)
  # This tier is deliberately excluded from unit, regression and all.
  prepare_database linpam_load
  docker compose -f compose.yaml -f compose.load.yaml build load-controlplane load-generator load-users
  docker compose -f compose.yaml -f compose.load.yaml stop load-controlplane
  docker compose -f compose.yaml -f compose.load.yaml run --rm load-users
  docker compose exec -T postgres psql -U linpam -d linpam_load -c 'TRUNCATE users,server_groups,roles,system_state,runtime_settings,user_groups,unix_groups RESTART IDENTITY CASCADE' >/dev/null
  trap 'docker compose -f compose.yaml -f compose.load.yaml stop load-controlplane load-rabbitmq load-gateway >/dev/null' EXIT
  docker compose -f compose.yaml -f compose.load.yaml up -d load-controlplane load-gateway
  docker compose -f compose.yaml -f compose.load.yaml run --rm load-generator
  ;;
 all)
  sh scripts/test.sh unit
  sh scripts/test.sh regression
  ;;
 *) printf 'Usage: scripts/test.sh [unit|regression|ui|integration|e2e|load|all]\n' >&2; exit 2 ;;
esac
