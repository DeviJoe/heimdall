#!/usr/bin/env python3
"""Exercise real API, Linux accounts, SSH, sudo, outages and revocation on the Compose demo."""
import fcntl, http.cookiejar, json, pathlib, secrets, subprocess, time, urllib.error, urllib.request, uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASE = 'http://localhost:5180'
secrets_env = dict(line.split('=', 1) for line in (ROOT / '.env').read_text().splitlines() if '=' in line)
jar = http.cookiejar.CookieJar()
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
results = []
created_fixtures = {}
_lock = None
def lock_stand():
    global _lock
    (ROOT / ".local").mkdir(exist_ok=True)
    _lock = (ROOT / ".local/acceptance.lock").open("a")
    fcntl.flock(_lock, fcntl.LOCK_EX)

def login_admin():
    # A private Compose-only fixture avoids changing a person's factors.
    # This setup requires local database administration; no bypass API exists.
    config=(ROOT/'config/controlplane.yaml').read_text()
    assert 'development: true' in config, 'acceptance fixture is only permitted in the development stand'
    path=ROOT/'.local/acceptance-credentials.json'
    fixture=json.loads(path.read_text()) if path.exists() else None
    if fixture:
        ident=str(uuid.UUID(fixture['id']))
        active=compose('exec','-T','postgres','psql','-U','linpam','-d','linpam','-Atc',"SELECT status='active' AND source='acceptance-fixture' AND totp_secret='' AND NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id) FROM users u WHERE id='"+ident+"'").strip()=='t'
        if not active: fixture=None
    if not fixture:
        fixture={'id':str(uuid.uuid4()),'login':'acceptance_'+secrets.token_hex(4),'password':secrets.token_urlsafe(40)}
        result=subprocess.run(['go','run','./scripts/acceptance-auth'],cwd=ROOT,input=json.dumps({'password':fixture['password']}),capture_output=True,text=True,check=True)
        hash_value=json.loads(result.stdout)['hash']
        role_id=str(uuid.uuid4())
        sql="BEGIN; INSERT INTO roles(id,name,permissions,linux_access) VALUES ('"+role_id+"','Acceptance fixture','[\"*\"]',false) ON CONFLICT(name) DO NOTHING; INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,password_hash,source) SELECT '"+fixture['id']+"','"+fixture['login']+"','Acceptance fixture','active',v,v,'/home/"+fixture['login']+"','/usr/sbin/nologin','"+hash_value+"','acceptance-fixture' FROM (SELECT nextval('posix_ids')::int v) q; INSERT INTO role_bindings(id,user_id,role_id,group_id) SELECT gen_random_uuid(),'"+fixture['id']+"',id,'*' FROM roles WHERE name='Acceptance fixture' AND permissions @> '[\"*\"]'; INSERT INTO audit_events(actor_id,channel,action,resource_id) VALUES('acceptance','fixture','acceptance.create','"+fixture['id']+"'); COMMIT;"
        subprocess.run(['docker','compose','exec','-T','postgres','psql','-U','linpam','-d','linpam','-v','ON_ERROR_STOP=1'],cwd=ROOT,input=sql,capture_output=True,text=True,check=True)
        path.write_text(json.dumps(fixture));path.chmod(0o600)
    jar.clear()
    result=request('/auth/login','POST',{'login':fixture['login'],'password':fixture['password']})
    assert result.get('authenticated'), 'fixture account unexpectedly requires a factor'
    return fixture['login']

def cleanup_admin_fixture():
    # Cleanup only IDs returned by this test process's user creation calls.
    # Keep tombstones/audit/native home data, and avoid leaving active test
    # accounts behind when a regression fails halfway through a scenario.
    if created_fixtures:
        login_admin()
        for ident, login in list(created_fixtures.items()):
            user = request('/users/'+ident)
            if user['status'] != 'deleted': request('/users/'+ident+'/status','POST',{'status':'deleted'})
            for suffix in ['', '.pub']:
                (ROOT/'.local'/('key-'+login+suffix)).unlink(missing_ok=True)
            del created_fixtures[ident]
    path=ROOT/'.local/acceptance-credentials.json'
    if not path.exists(): return
    fixture=json.loads(path.read_text());ident=str(uuid.UUID(fixture['id']))
    owner="SELECT id FROM users WHERE id='"+ident+"' AND source='acceptance-fixture'"
    sql="BEGIN; UPDATE users SET status='deleted',password_hash='',auth_version=auth_version+1 WHERE id IN("+owner+"); UPDATE api_tokens SET revoked_at=now() WHERE user_id IN("+owner+"); DELETE FROM role_bindings WHERE user_id IN("+owner+"); DELETE FROM roles r WHERE r.name='Acceptance fixture' AND r.permissions='[\"*\"]'::jsonb AND NOT r.linux_access AND NOT EXISTS(SELECT 1 FROM role_bindings b WHERE b.role_id=r.id) AND NOT EXISTS(SELECT 1 FROM user_group_role_bindings b WHERE b.role_id=r.id) AND NOT EXISTS(SELECT 1 FROM unix_group_role_bindings b WHERE b.role_id=r.id); INSERT INTO audit_events(actor_id,channel,action,resource_id) SELECT 'acceptance','fixture','acceptance.cleanup',id::text FROM users WHERE id IN("+owner+"); COMMIT;"
    subprocess.run(['docker','compose','exec','-T','postgres','psql','-U','linpam','-d','linpam','-v','ON_ERROR_STOP=1'],cwd=ROOT,input=sql,capture_output=True,text=True,check=True)
    path.unlink()

def request(path, method='GET', data=None, bearer=None, expected=200):
    headers = {'Content-Type': 'application/json', 'X-Heimdall-CSRF': '1', 'Origin': BASE}
    if bearer: headers['Authorization'] = 'Bearer ' + bearer
    req = urllib.request.Request(BASE + '/api/v1' + path, headers=headers, method=method, data=None if data is None else json.dumps(data).encode())
    try:
        response = client.open(req, timeout=15)
        status, body = response.status, response.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    if status != expected:
        raise AssertionError(f'{method} {path}: HTTP {status} instead of {expected}: {body[:300].decode()}')
    result = json.loads(body or '{}')
    if method == 'POST' and path == '/users' and status == 201:
        created_fixtures[result['user']['id']] = result['user']['login']
    return result

def compose(*args):
    return subprocess.run(['docker', 'compose', *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout

def managed_directory():
    return compose('exec','-T','linux-node','sh','-c','if [ -d /etc/linpam/users ]; then echo /etc/linpam; else echo /etc/heimdall; fi').strip()

def cleanup_ephemeral_node(node, expected_name):
    # Only a caller-created disposable fixture may use this helper. Keep audit/operations.
    assert node['name'] == expected_name and (expected_name == 'enrollment-acceptance' or expected_name.startswith('freebsd-regression-'))
    ident=str(uuid.UUID(node['id']))
    name=expected_name.replace("'", "''")
    sql="BEGIN; DELETE FROM sync_targets WHERE node_id='"+ident+"'; DELETE FROM sync_resources WHERE node_id='"+ident+"'; DELETE FROM node_accounts WHERE node_id='"+ident+"'; DELETE FROM node_recovery_tokens WHERE node_id='"+ident+"'; DELETE FROM security_events WHERE node_id='"+ident+"'; UPDATE incidents SET node_id=NULL,status='resolved' WHERE node_id='"+ident+"'; DELETE FROM nodes WHERE id='"+ident+"' AND name='"+name+"'; COMMIT;"
    compose('exec','-T','postgres','psql','-U','linpam','-d','linpam','-v','ON_ERROR_STOP=1','-c',sql)

def wait_for(fn, seconds=75):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
            if last: return last
        except (urllib.error.URLError, TimeoutError, ConnectionError, AssertionError) as e: last = str(e)
        time.sleep(1)
    raise AssertionError('Condition did not converge: ' + str(last))

def passed(name):
    results.append(name)
    print('PASS', name, flush=True)

def mcp_request(secret,tool,arguments=None,expected=200):
    body={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':tool,'arguments':arguments or {}}}
    req=urllib.request.Request(BASE+'/mcp',data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+secret,'Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-11-25'},method='POST')
    try:
        response=urllib.request.urlopen(req,timeout=15);status,body=response.status,response.read()
    except urllib.error.HTTPError as e:status,body=e.code,e.read()
    assert status==expected,f'MCP HTTP {status}: {body[:200]}'
    return json.loads(body)

def ssh(login, key, command, success=True):
    result = subprocess.run(['ssh', '-F', '/dev/null', '-i', str(key), '-p', secrets_env.get('HEIMDALL_SSH_PORT', '22220'), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile=' + str(ROOT / '.local/known_hosts'), login + '@localhost', command], capture_output=True, text=True, timeout=15)
    assert (result.returncode == 0) == success, f'SSH result differs from expectation: {result.stderr}'
    return result.stdout

def synced():
    nodes = request('/nodes')
    return nodes and all(n['desired_revision'] == n['applied_revision'] and n['status'] == 'in_sync' for n in nodes if not n['disabled'])

def main():
    lock_stand()
    login_admin()
    wait_for(synced)
    groups, roles = request('/groups'), request('/roles')
    group = next(g for g in groups if g['name'] == 'Demo Linux')
    role = next(r for r in roles if r['name'] == 'Linux operator')
    login = 'verify_' + secrets.token_hex(3)
    created = request('/users', 'POST', {'login': login, 'display_name': 'Verification operator', 'sync_to_nodes': True}, expected=201)
    uid = created['user']['id']
    password = 'Test-' + secrets.token_urlsafe(20)
    # Separate browser session for invitation and self-service.
    admin_cookies = list(jar)
    jar.clear()
    request('/auth/invitation', 'POST', {'token': created['invitation_url'].split('#')[1], 'password': password})
    request('/users', 'POST', {'login': 'forbidden', 'display_name': 'Forbidden'}, expected=403)
    key = ROOT / '.local' / ('key-' + login)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    public = key.with_suffix('.pub').read_text()
    added = request('/users/' + uid + '/keys', 'POST', {'name': 'Verification key', 'public_key': public}, expected=201)
    request('/users/' + uid + '/linux-password', 'PUT', {'password': password}, expected=403)
    jar.clear()
    for cookie in admin_cookies: jar.set_cookie(cookie)
    request('/bindings', 'POST', {'user_id': uid, 'role_id': role['id'], 'group_id': group['id']})
    wait_for(synced)
    effective = compose('exec', '-T', 'linux-node', '/usr/sbin/sshd', '-T', '-C', 'user='+login+',host=localhost,addr=127.0.0.1')
    assert 'passwordauthentication no' in effective and 'pubkeyauthentication yes' in effective
    passed('SSH login methods require explicit role permissions; UNIX password denied by default')
    output = ssh(login, key, 'id; sudo -n /usr/bin/id; sudo -n /usr/bin/whoami')
    assert 'uid=0(root)' in output and output.rstrip().endswith('root'), output
    passed('Real Linux account, public-key SSH and scoped sudo')
    token = request('/tokens', 'POST', {'name': 'Verification read token', 'audiences': ['api', 'mcp'], 'scopes': ['nodes.read'], 'groups': [group['id']], 'expires_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() + 3600))})
    request('/nodes', bearer=token['secret'])
    request('/users', bearer=token['secret'], expected=403)
    request('/users/' + uid + '/status', 'POST', {'status': 'disabled'}, bearer=token['secret'], expected=403)
    passed('API scopes and group RBAC reject privilege escalation')
    assert not mcp_request(token['secret'],'list_nodes')['result'].get('isError')
    assert mcp_request(token['secret'],'disable_user',{'user_id':uid})['result']['isError']
    passed('Real MCP transport shares current API scopes and rejects unauthorized tools')
    compose('exec', '-T', 'linux-node', 'sh', '-c', 'kill -TERM "$(cat /run/linpam/agent.pid)"')
    compose('stop', 'controlplane')
    try:
        assert 'uid=0(root)' in ssh(login, key, 'id; sudo -n /usr/bin/id')
        passed('SSH and sudo survive stopped agent and control plane')
        def alert():
            data = json.load(urllib.request.urlopen('http://localhost:9093/api/v2/alerts', timeout=5))
            return any(x['labels'].get('alertname') == 'HeimdallControlPlaneUnavailable' for x in data)
        wait_for(alert, 45)
        passed('External monitoring detects unavailable control plane')
    finally:
        compose('start', 'controlplane')
    wait_for(lambda: request('/me'))
    blocked = request('/users/' + uid + '/status', 'POST', {'status': 'disabled'})
    assert any(n['desired_revision'] > n['applied_revision'] for n in request('/nodes'))
    assert 'uid=' in ssh(login, key, 'id')
    wait_for(lambda: any(i['kind'] == 'revocation_pending' and i['status'] != 'resolved' for i in request('/incidents')), 45)
    passed('Offline revocation remains pending and creates critical incident')
    compose('restart', 'linux-node')
    wait_for(synced)
    ssh(login, key, 'id', success=False)
    managed = managed_directory()
    prefix = 'linpam_' if managed == '/etc/linpam' else 'heimdall_'
    node_check = compose('exec', '-T', 'linux-node', 'sh', '-c', f'test ! -s {managed}/authorized_keys/{login} && getent shadow {login} | awk -F: \'{{exit !($2=="*" && $8=="1")}}\' && ! grep -q "^{login} " /etc/sudoers.d/{prefix}{login}')
    assert node_check == ''
    passed('Revocation clears key and password, expires account and removes sudo')
    request('/users/' + uid + '/status', 'POST', {'status': 'active'})
    request('/users/' + uid + '/keys', 'POST', {'name': 'Cannot reuse', 'public_key': public}, expected=409)
    passed('Revoked SSH fingerprints cannot be reused')
    request('/tokens/' + token['token']['id'], 'DELETE')
    request('/nodes', bearer=token['secret'], expected=401)
    mcp_request(token['secret'],'list_nodes',expected=401)
    passed('Revoked API token is immediately rejected')
    # Separate fixture: keep an authenticated SSH session, a detached user job,
    # and a sudo root descendant alive when the agent applies a full revoke.
    session_login = 'sessions_' + secrets.token_hex(3)
    session_created = request('/users', 'POST', {'login': session_login, 'kind': 'service', 'sync_to_nodes': True}, expected=201)
    session_uid = session_created['user']['id']
    session_role_id = str(uuid.uuid4())
    request('/roles', 'POST', {'id': session_role_id, 'name': 'Session teardown '+session_login, 'permissions': [], 'linux_access': True, 'allow_ssh_keys': True, 'allow_password': False, 'sudo': [], 'sudoers': 'ALL=(root) NOPASSWD: /usr/bin/sleep 120'})
    request('/bindings', 'POST', {'user_id': session_uid, 'role_id': session_role_id, 'group_id': group['id']})
    session_key = ROOT / '.local' / ('key-' + session_login)
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(session_key)], check=True)
    request('/users/'+session_uid+'/keys', 'POST', {'name': 'Teardown test', 'public_key': session_key.with_suffix('.pub').read_text()}, expected=201)
    session = None
    try:
        wait_for(synced)
        command = 'nohup /usr/bin/sleep 120 >/dev/null 2>&1 & sudo -n /usr/bin/sleep 120 & echo ready; wait'
        session = subprocess.Popen(['ssh', '-F', '/dev/null', '-i', str(session_key), '-p', secrets_env.get('HEIMDALL_SSH_PORT', '22220'), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile='+str(ROOT/'.local/known_hosts'), session_login+'@localhost', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def process_rows():
            rows = compose('exec','-T','linux-node','ps','-eo','pid=,ppid=,uid=,stat=,comm=').splitlines()
            return [line.split() for line in rows if len(line.split()) == 5 and not line.split()[3].startswith('Z')]
        def root_children():
            rows = process_rows()
            owned = {int(row[0]) for row in rows if int(row[2]) == session_created['user']['uid']}
            for _ in range(10):
                children = {int(row[0]) for row in rows if int(row[1]) in owned}
                if children <= owned: break
                owned |= children
            return [int(row[0]) for row in rows if int(row[0]) in owned and int(row[2]) == 0 and row[4] == 'sleep'] if session.poll() is None else []
        root_pids = wait_for(root_children)
        revoked = request('/users/'+session_uid+'/status','POST',{'status':'disabled'})
        wait_for(synced)
        session.wait(timeout=10)
        assert session.returncode != 0, 'authenticated SSH connection survived revocation'
        assert compose('exec','-T','linux-node','sh','-c','! pgrep -u '+str(session_created['user']['uid'])+' >/dev/null') == ''
        assert not set(root_pids) & {int(row[0]) for row in process_rows()}, 'sudo descendant survived ACK'
        ssh(session_login,session_key,'id',success=False)
        passed('Full revocation terminates existing SSH connection, nohup job and sudo root descendant before ACK')
    finally:
        if session and session.poll() is None: session.terminate();session.wait(timeout=10)
        request('/users/'+session_uid+'/status','POST',{'status':'deleted'})
        request('/roles/'+session_role_id,'DELETE')
        session_key.unlink(missing_ok=True);session_key.with_suffix('.pub').unlink(missing_ok=True)
    request('/users/' + uid + '/status', 'POST', {'status': 'deleted'})
    wait_for(synced)
    report = {'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'checks': results, 'revocation_operation': blocked['operation_id'], 'revoked_key_id': added['key']['id']}
    (ROOT / '.local/verification.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print('All checks passed. Report: .local/verification.json', flush=True)

if __name__ == '__main__':
    try:
        main()
    finally:
        cleanup_admin_fixture()
