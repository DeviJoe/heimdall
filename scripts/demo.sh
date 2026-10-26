#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p .local
if [ ! -f .env ]; then
  python3 - <<'PY'
import hashlib, pathlib, secrets
password = secrets.token_urlsafe(32)
values = {
 'HEIMDALL_ADMIN_PASSWORD': 'Demo-' + secrets.token_urlsafe(18),
 'HEIMDALL_DATABASE_PASSWORD': secrets.token_urlsafe(32),
 'HEIMDALL_REDIS_PASSWORD': secrets.token_urlsafe(32),
 'HEIMDALL_ENCRYPTION_KEY': secrets.token_urlsafe(32),
 'HEIMDALL_JOIN_TOKEN': secrets.token_urlsafe(32),
 'HEIMDALL_METRICS_PASSWORD_HASH': hashlib.sha256(password.encode()).hexdigest(),
}
pathlib.Path('.env').write_text(''.join(f'{k}={v}\n' for k,v in values.items()))
pathlib.Path('.local/metrics-password').write_text(password)
print('Created local demo secrets in .env (mode 0600). Login: admin.')
PY
fi
python3 - <<'PY'
import pathlib, secrets
path = pathlib.Path('.env')
text = path.read_text()
values = dict(line.split('=',1) for line in text.splitlines() if '=' in line)
for key, value in values.items():
 if key.startswith('LINPAM_') and key.replace('LINPAM_', 'HEIMDALL_', 1) not in values:
  text += key.replace('LINPAM_', 'HEIMDALL_', 1)+'='+value+'\n'
for key in ['HEIMDALL_RABBITMQ_PASSWORD', 'HEIMDALL_GRAFANA_PASSWORD']:
 if not any(line.startswith(key+'=') for line in text.splitlines()): text += key+'='+secrets.token_urlsafe(32)+'\n'
path.write_text(text)
PY
chmod 600 .env .local/metrics-password
chmod +x deployments/node-entrypoint.sh
docker compose up -d --build
if command -v ssh-keygen >/dev/null 2>&1; then python3 scripts/seed-demo.py; fi
printf '\nHeimdall: http://localhost:5180\nLogin: admin. Password: HEIMDALL_ADMIN_PASSWORD in .env\nSSH: linux-demo :22220 · linux-stage :22222 · linux-web :22223 · linux-db :22224\nGrafana: http://localhost:3001 (admin, HEIMDALL_GRAFANA_PASSWORD in .env)\nPrometheus: http://localhost:9091 · Alertmanager: http://localhost:9093\n'
