#!/usr/bin/env python3
"""Functional FreeBSD regression on a disposable VM, never on a production host."""
import importlib.util, json, os, pathlib, secrets, shlex, subprocess, time, uuid
spec = importlib.util.spec_from_file_location('demo', pathlib.Path(__file__).with_name('check-demo.py'))
d = importlib.util.module_from_spec(spec); spec.loader.exec_module(d)
VM = d.ROOT / '.local/freebsd'
HOST = os.getenv('HEIMDALL_FREEBSD_HOST', '127.0.0.1')
PORT = os.getenv('HEIMDALL_FREEBSD_PORT', '22221')
KEY = pathlib.Path(os.getenv('HEIMDALL_FREEBSD_KEY', str(VM / 'vm-key')))
SSH = ['ssh', '-F', '/dev/null', '-i', str(KEY), '-p', PORT, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'UserKnownHostsFile='+str(VM / 'known_hosts'), 'root@'+HOST]
def remote(command, data=None):
    return subprocess.run(SSH+[command], input=data, capture_output=True, text=True, timeout=90, check=True).stdout

def user_ssh(login, key, command, success=True):
    args = SSH.copy(); args[args.index(str(KEY))] = str(key); args[-1] = login+'@'+HOST
    result = subprocess.run(args+[command], capture_output=True, text=True, timeout=15)
    assert (result.returncode == 0) == success, result.stderr
    return result.stdout

def main():
    d.lock_stand()
    # This explicit VM marker is provisioned by the test harness outside the agent.
    assert remote('uname -s; test -f /var/run/heimdall-test-vm && echo disposable').splitlines() == ['FreeBSD', 'disposable']
    architecture = remote('uname -p').strip()
    arch = {'aarch64':'arm64', 'amd64':'amd64'}[architecture]
    subprocess.run(['make', 'agent-freebsd'], cwd=d.ROOT, env=dict(os.environ, ARCH=arch), check=True, stdout=subprocess.DEVNULL)
    d.login_admin()
    suffix = secrets.token_hex(3)
    group = d.request('/groups', 'POST', {'name':'FreeBSD regression '+suffix})
    # Group creation returns a sync operation. Resolve its concrete group ID.
    group = next(g for g in d.request('/groups') if g['name']=='FreeBSD regression '+suffix)
    join = d.request('/join-tokens','POST',{'group_id':group['id'],'max_uses':1,'ttl_seconds':300})['token']
    name = 'freebsd-regression-'+suffix
    created = d.request('/users','POST',{'login':'bsd_'+suffix,'display_name':'FreeBSD regression','sync_to_nodes':True},expected=201)
    user = created['user']; node = None; token = None; unix_group = None; role = None; session = None
    key = VM / ('user-'+suffix)
    subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
    password = 'FreeBSD-'+secrets.token_urlsafe(24)
    admin_cookies = list(d.jar)
    try:
        d.jar.clear()
        d.request('/auth/invitation','POST',{'token':created['invitation_url'].split('#')[1],'password':password})
        d.request('/users/'+user['id']+'/keys','POST',{'name':'FreeBSD regression','public_key':key.with_suffix('.pub').read_text()},expected=201)
        d.request('/users/'+user['id']+'/linux-password','PUT',{'password':password},expected=403)
        d.jar.clear()
        for cookie in admin_cookies: d.jar.set_cookie(cookie)
        d.request('/roles','POST',{'name':'FreeBSD native '+suffix,'permissions':[],'linux_access':True,'allow_password':True,'allow_ssh_keys':True,'sudo':[],'sudoers':'ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/whoami'})
        role=next(r for r in d.request('/roles') if r['name']=='FreeBSD native '+suffix)
        d.request('/bindings','POST',{'user_id':user['id'],'role_id':role['id'],'group_id':group['id']})
        d.request('/users/'+user['id']+'/linux-password','PUT',{'password':password})
        remote('service heimdall_agent onestop >/dev/null 2>&1 || true; service heimdall_helper onestop >/dev/null 2>&1 || true; mkdir -p /root/heimdall-release; chmod 700 /root/heimdall-release')
        # Only the explicitly disposable VM's agent state is reset, never native user data.
        remote('rm -rf /var/db/heimdall-agent /var/db/heimdall-helper')
        for path in [VM/'heimdall-agent',*(d.ROOT/'deployments/freebsd').iterdir()]:
            if path.is_file():
                args=['scp','-F','/dev/null','-i',str(KEY),'-P',PORT,'-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(VM/'known_hosts'),str(path),'root@'+HOST+':/root/heimdall-release/'+path.name]
                subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        remote('cd /root/heimdall-release && sh install.sh')
        for filename in ['ca.pem','state.pub']:
            d.compose('cp','linux-node:/trust/'+filename,str(VM/filename))
            data=(VM/filename).read_bytes()
            subprocess.run(SSH+['umask 022; cat > /usr/local/etc/heimdall/'+filename],input=data,check=True,stdout=subprocess.DEVNULL)
        api=os.getenv('HEIMDALL_FREEBSD_API','https://10.0.2.2:8443')
        grpc=os.getenv('HEIMDALL_FREEBSD_GRPC','10.0.2.2:9443')
        values={'api':api,'grpc':grpc,'server_name':'controlplane','name':name,'join_token':join,'ca_file':'/usr/local/etc/heimdall/ca.pem','state_key':'/usr/local/etc/heimdall/state.pub','state_dir':'/var/db/heimdall-agent','worker_state_dir':'/var/db/heimdall-helper','socket':'/var/run/heimdall/helper.sock','auth_log':'/var/log/auth.log','run_as':'heimdall-agent','heartbeat':'15s'}
        config=''.join(k+': '+json.dumps(v)+'\n' for k,v in values.items())
        remote('umask 077; cat > /usr/local/etc/heimdall/agent.yaml',config)
        remote("test -d /home || mkdir -p /usr/home; test -e /home || ln -s /usr/home /home; sshd -t; sysrc heimdall_helper_enable=NO heimdall_agent_enable=YES; service heimdall_agent start")
        node=d.wait_for(lambda:next((n for n in d.request('/nodes') if n['name']==name and n['status']=='in_sync'),None),100)
        checkpoint=json.loads(remote('cat /var/db/heimdall-helper/checkpoint.json'))
        assert checkpoint['node_id']==node['id']
        output=user_ssh(user['login'],key,'id; sudo -n /usr/bin/id; sudo -n /usr/bin/whoami')
        assert 'uid=0(root)' in output and output.rstrip().endswith('root'),output
        assert remote('pw usershow -n '+user['login']).split(':')[1].startswith('$6$')
        shell=remote('getent passwd '+user['login']).strip().split(':')[-1]
        assert shell=='/usr/local/bin/bash',shell
        d.passed('FreeBSD pw accounts, hashed password, signed enrollment, OpenSSH and sudo')
        d.request('/unix-groups','POST',{'name':'bsdgrp_'+suffix,'gid':0,'members':[user['id']]})
        unix_group=next(g for g in d.request('/unix-groups') if g['name']=='bsdgrp_'+suffix)
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        assert unix_group['name'] in user_ssh(user['login'],key,'id')
        d.request('/unix-groups','POST',{'id':unix_group['id'],'name':unix_group['name'],'gid':unix_group['gid'],'members':[]})
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        assert unix_group['name'] not in user_ssh(user['login'],key,'id')
        d.passed('FreeBSD named UNIX groups and supplementary membership grant/removal')

        role['sudoers'] += ', /bin/sleep 120'
        d.request('/roles','POST',role)
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        args = SSH.copy(); args[args.index(str(KEY))] = str(key); args[-1] = user['login']+'@'+HOST
        session = subprocess.Popen(args+['nohup /bin/sleep 120 >/dev/null 2>&1 & sudo -n /bin/sleep 120 & echo ready; wait'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def process_rows():
            return [parts for line in remote('LC_ALL=C /bin/ps -ax -o pid=,ppid=,uid=,stat=,comm=').splitlines() if len(parts:=line.split())==5 and not parts[3].startswith('Z')]
        def root_children():
            rows = process_rows()
            owned = {int(row[0]) for row in rows if int(row[2])==user['uid']}
            for _ in range(10):
                children = {int(row[0]) for row in rows if int(row[1]) in owned}
                if children <= owned: break
                owned |= children
            return [int(row[0]) for row in rows if int(row[0]) in owned and int(row[2])==0 and row[4].split('/')[-1]=='sleep']
        root_pids = d.wait_for(root_children,20)

        remote('service heimdall_agent stop')
        assert 'uid=0(root)' in user_ssh(user['login'],key,'sudo -n /usr/bin/id')
        d.passed('FreeBSD SSH and sudo survive stopped single-binary agent')
        d.request('/users/'+user['id']+'/status','POST',{'status':'disabled'})
        assert 'uid=' in user_ssh(user['login'],key,'id')
        remote('service heimdall_agent start')
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        user_ssh(user['login'],key,'id',success=False)
        assert remote('cat /etc/heimdall/authorized_keys/'+user['login'])==''
        fields=remote('pw usershow -n '+user['login']).strip().split(':')
        assert fields[1]=='*' and fields[6]=='86400' and fields[9]=='/usr/sbin/nologin'
        d.passed('FreeBSD revocation clears keys/password/sudo and expires the native account')
        session.wait(timeout=10)
        assert session.returncode != 0, 'FreeBSD SSH connection survived revocation'
        remaining = process_rows()
        assert all(int(row[2])!=user['uid'] for row in remaining), 'FreeBSD user process survived ACK'
        assert not set(root_pids) & {int(row[0]) for row in remaining}, 'FreeBSD sudo descendant survived ACK'
        d.passed('FreeBSD full revocation terminates SSH session, detached job and sudo root descendant before ACK')
        # Migrate while disabled; account identity changes must not grant access.
        newlogin=user['login']+'_m'; home='/usr/home/'+newlogin
        d.request('/users/'+user['id'],'PUT',dict(user,login=newlogin,uid=user['uid']+100000,gid=user['gid']+100000,home=home,maintenance=True))
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        assert remote('getent passwd '+newlogin).strip().split(':')[5]==home
        user_ssh(newlogin,key,'id',success=False)
        d.passed('FreeBSD disabled UID/GID/login/home migration preserves revocation')
        d.request('/users/'+user['id']+'/status','POST',{'status':'active'})
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        user_ssh(newlogin,key,'id',success=False)
        freshkey=VM / ('fresh-'+suffix)
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(freshkey)],check=True)
        d.request('/users/'+user['id']+'/keys','POST',{'name':'New FreeBSD key','public_key':freshkey.with_suffix('.pub').read_text()},expected=201)
        d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),100)
        assert 'uid=0(root)' in user_ssh(newlogin,freshkey,'sudo -n /usr/bin/id')
        freshkey.unlink();freshkey.with_suffix('.pub').unlink()
        d.passed('FreeBSD reactivation retains old key ban and permits a newly issued key')
        (d.ROOT/'.local/freebsd-verification.json').write_text(json.dumps({'checks':d.results,'platform':remote('uname -srm').strip(),'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
    finally:
        if session and session.poll() is None: session.terminate(); session.wait(timeout=10)
        if node is None:
            node=next((n for n in d.request('/nodes') if n['name']==name),None)
        d.jar.clear()
        for cookie in admin_cookies:d.jar.set_cookie(cookie)
        d.request('/users/'+user['id']+'/status','POST',{'status':'deleted'})
        if node:
            d.wait_for(lambda:next((n for n in d.request('/nodes') if n['id']==node['id'] and n['status']=='in_sync'),None),60)
            d.request('/nodes/'+node['id'],'PUT',{'group_id':group['id'],'disabled':True})
        remote('service heimdall_agent onestop >/dev/null 2>&1 || true; service heimdall_helper onestop >/dev/null 2>&1 || true')
        if node: d.cleanup_ephemeral_node(node,name)
        if unix_group: d.request('/unix-groups/'+unix_group['id'],'DELETE')
        if role: d.request('/roles/'+role['id'],'DELETE')
        d.request('/groups/'+group['id'],'DELETE')
        key.unlink(missing_ok=True);key.with_suffix('.pub').unlink(missing_ok=True)
    print('FreeBSD functional regression passed.',flush=True)
if __name__ == '__main__':
    try:
        main()
    finally:
        d.cleanup_admin_fixture()
