#!/bin/sh
set -eu
mkdir -p /run/sshd /run/linpam /var/lib/heimdall-agent /var/lib/heimdall-helper
chown 998:998 /var/lib/heimdall-agent
chmod 700 /var/lib/heimdall-agent /var/lib/heimdall-helper
cp /usr/share/heimdall/sshd_config /etc/ssh/sshd_config
if [ -d /etc/linpam/users ]; then sed -i 's#/etc/heimdall/#/etc/linpam/#g' /etc/ssh/sshd_config; fi
ssh-keygen -A
touch /var/log/auth.log
chmod 600 /var/log/auth.log
/usr/sbin/sshd -D -E /var/log/auth.log &
SSHD_PID=$!
# Persisted pre-rename /etc volumes keep the service UID under its old name.
AGENT_USER=$(getent passwd 998 | cut -d: -f1)
heimdall-agent --run-as "$AGENT_USER" --api "${HEIMDALL_AGENT_API:-https://controlplane:8443}" --grpc "${HEIMDALL_AGENT_GRPC:-controlplane:9443}" --name "${HEIMDALL_NODE_NAME:-linux-demo}" &
AGENT_PID=$!
echo "$AGENT_PID" > /run/linpam/agent.pid
echo "$AGENT_PID" > /run/linpam/helper.pid
trap 'kill "$SSHD_PID" "$AGENT_PID" 2>/dev/null || true; exit 0' TERM INT
# The agent has an independent lifecycle. Its failure never stops SSH or deletes local state.
while kill -0 "$SSHD_PID" 2>/dev/null; do sleep 2 & wait $! || true; done
exit 1
