#!/bin/sh
# Run from a release directory containing FreeBSD binaries and these rc scripts.
set -eu
[ "$(uname -s)" = FreeBSD ] && [ "$(id -u)" = 0 ] || { echo 'Requires root on FreeBSD' >&2; exit 1; }
cd "$(dirname "$0")"
[ -x /usr/local/sbin/visudo ] || { echo 'Install sudo first: pkg install sudo' >&2; exit 1; }
# An existing unrelated UID or GID must never be adopted.
if ! pw usershow heimdall-agent >/dev/null 2>&1; then
 if pw usershow -u 998 >/dev/null 2>&1 || pw groupshow -g 998 >/dev/null 2>&1; then
  echo 'UID/GID 998 is already allocated; resolve the service identity before installation' >&2; exit 1
 fi
 pw groupadd heimdall-agent -g 998
 pw useradd heimdall-agent -u 998 -g 998 -d /nonexistent -s /usr/sbin/nologin -h -
fi
[ "$(id -u heimdall-agent)" = 998 ] && [ "$(id -g heimdall-agent)" = 998 ] || exit 1
install -o root -g wheel -m 0755 heimdall-agent /usr/local/sbin/
install -o root -g wheel -m 0555 heimdall_agent /usr/local/etc/rc.d/
install -d -o root -g wheel -m 0755 /usr/local/etc/heimdall /etc/heimdall/authorized_keys /etc/heimdall/users /etc/heimdall/groups
install -d -o root -g wheel -m 0700 /var/db/heimdall-helper
install -d -o heimdall-agent -g heimdall-agent -m 0700 /var/db/heimdall-agent
if [ ! -f /usr/local/etc/heimdall/agent.yaml ]; then
 install -o root -g wheel -m 0600 agent.yaml.example /usr/local/etc/heimdall/agent.yaml
fi
printf 'Installed. Configure agent.yaml and trusted ca.pem/state.pub, then configure sshd and enable heimdall_agent as documented.\n'
