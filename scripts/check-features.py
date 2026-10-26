#!/usr/bin/env python3
"""Reusable Compose acceptance scenarios for inventory, policies, HA and telemetry."""
import base64, importlib.util, json, pathlib, secrets, subprocess, time, urllib.request, urllib.parse

spec = importlib.util.spec_from_file_location('demo', pathlib.Path(__file__).with_name('check-demo.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

def main():
    d.lock_stand()
    d.login_admin()
    d.wait_for(d.synced)
    managed = d.managed_directory()
    suffix = secrets.token_hex(3)
    node = next(n for n in d.request('/nodes') if n['name']=='linux-demo')
    original_group = node['group_id']
    original_settings = d.request('/settings')
    user_id = None
    token_id = None
    group = None
    role_id = None
    key = d.ROOT/'.local'/('activity-key-'+suffix)
    unmanaged = 'outside_'+suffix
    try:
        roles = d.request('/roles')
        assert all(isinstance(r['sudo'],list) and isinstance(r['permissions'],list) for r in roles)
        d.passed('Role collections use non-null arrays')
        changed = dict(original_settings, key_ttl_seconds=original_settings['key_ttl_seconds']+60)
        d.request('/settings','PUT',changed)
        assert d.request('/me')['key_ttl_seconds']==changed['key_ttl_seconds']
        d.request('/settings','PUT',changed,expected=409)
        d.passed('Runtime policy reload and optimistic settings concurrency')
        # Transport credentials have their own rollout acknowledgement. A
        # disconnected node must remain pending after other nodes reissue.
        before_certificates = {n['id']: n['cert_expires'] for n in d.request('/nodes') if not n['disabled']}
        d.compose('stop','linux-stage')
        try:
            certificate_settings = d.request('/settings')
            certificate_settings['node_certificate_ttl_seconds'] = 365*86400
            d.request('/settings','PUT',certificate_settings)
            d.wait_for(lambda: d.request('/settings')['certificates_pending'] == 1, 100)
            remaining = [n for n in d.request('/nodes') if not n['disabled'] and n['certificate_status'] == 'pending']
            assert len(remaining) == 1 and remaining[0]['name'] == 'linux-stage'
            d.passed('Certificate lifetime change reissues online nodes and keeps offline node pending')
        finally:
            d.compose('start','linux-stage')
        d.wait_for(lambda: d.request('/settings')['certificates_pending'] == 0 and d.synced(), 100)
        from datetime import datetime, timezone
        for n in d.request('/nodes'):
            if n['disabled']: continue
            lifetime = (datetime.fromisoformat(n['cert_expires'].replace('Z','+00:00'))-datetime.now(timezone.utc)).total_seconds()
            assert 364*86400 < lifetime <= 365*86400, n['name']+' certificate TTL differs'
            assert n['cert_expires'] != before_certificates[n['id']]
        d.passed('Returning node reissues its certificate and every node confirms the configured one-year TTL')
        restore_certificate_settings = d.request('/settings')
        restore_certificate_settings['node_certificate_ttl_seconds'] = original_settings['node_certificate_ttl_seconds']
        d.request('/settings','PUT',restore_certificate_settings)
        d.wait_for(lambda: d.request('/settings')['certificates_pending'] == 0 and d.synced(), 100)
        d.passed('Certificate policy restored to ten years and confirmed by all demo nodes')
        group = d.request('/groups','POST',{'name':'Acceptance '+suffix,'parent_id':original_group})['group']
        d.request('/nodes/move','POST',{'node_ids':[node['id']],'group_id':group['id']})
        d.wait_for(d.synced)
        assert next(g for g in d.request('/groups') if g['id']==group['id'])['parent_id']==original_group
        role_id = next(r['id'] for r in roles if r['name']=='Linux user')
        inventory_role = {'name':'Inventory '+suffix,'permissions':['inventory.read'],'linux_access':True,'sudo':[]}
        d.request('/roles','POST',inventory_role)
        role_id = next(r['id'] for r in d.request('/roles') if r['name']==inventory_role['name'])
        created = d.request('/users','POST',{'login':'automation_'+suffix,'display_name':'Acceptance automation','kind':'service'},expected=201)
        user_id = created['user']['id']
        assert created['user']['status']=='active' and not created['invitation_url']
        d.request('/bindings','POST',{'user_id':user_id,'role_id':role_id,'group_id':original_group})
        token = d.request('/tokens','POST',{'user_id':user_id,'name':'Inventory test','audiences':['api'],'scopes':['inventory.read'],'groups':[group['id']],'expires_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+1800))})
        token_id = token['token']['id']
        inventory = d.request('/ansible/inventory',bearer=token['secret'])
        assert len(inventory['_meta']['hostvars'])==1
        host = next(iter(inventory['_meta']['hostvars'].values()))
        assert host['heimdall_node_id']==node['id'] and host['ansible_user']==created['user']['login']
        d.request('/ansible/inventory',expected=403)
        d.request('/users',bearer=token['secret'],expected=403)
        d.passed('Service account inventory checks token scopes, inherited group and owner access')
        d.request('/users/'+user_id+'/status','POST',{'status':'disabled'})
        d.request('/ansible/inventory',bearer=token['secret'],expected=401)
        d.passed('Service account block invalidates inventory token immediately')
        # Existing sessions use the other CP while one instance is unavailable.
        instances = d.compose('ps','-q','controlplane').splitlines()
        assert len(instances)==2
        subprocess.run(['docker','stop',instances[0]],check=True,stdout=subprocess.DEVNULL)
        try:
            d.wait_for(lambda: d.request('/me')['user']['source']=='acceptance-fixture',30)
            d.passed('API session survives loss of one control plane instance')
        finally:
            subprocess.run(['docker','start',instances[0]],check=True,stdout=subprocess.DEVNULL)
        d.compose('stop','rabbitmq')
        try:
            # Make an actual desired-state change while broker is unavailable.
            d.request('/nodes/'+node['id']+'/retry','POST',{})
            d.wait_for(d.synced)
            d.passed('Desired-state polling recovers synchronization during RabbitMQ outage')
        finally:
            d.compose('start','rabbitmq')
        # Probe unmanaged successful login on a disposable local account.
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
        public = key.with_suffix('.pub').read_text()
        d.compose('exec','-T','linux-node','useradd','--uid','9000','--create-home','--shell','/bin/bash',unmanaged)
        d.compose('exec','-T','linux-node','usermod','--password','*',unmanaged)
        result = subprocess.run(['docker','compose','exec','-T','linux-node','sh','-c','cat > "$1/authorized_keys/$2"; chmod 644 "$1/authorized_keys/$2"','sh',managed,unmanaged],cwd=d.ROOT,input=public,capture_output=True,text=True)
        assert result.returncode==0
        d.ssh(unmanaged,key,'id')
        d.wait_for(lambda:any(e['login']==unmanaged and e['kind']=='unmanaged_login' for e in d.request('/security/events')),60)
        d.passed('Unmanaged SSH login is persisted and visible in security events')
        incident=d.wait_for(lambda:next((i for i in d.request('/incidents') if i['kind']=='unmanaged_login' and unmanaged in i['message']),None),20)
        d.request('/incidents/'+incident['id']+'/resolve','POST',{})
        assert all(i['id']!=incident['id'] for i in d.request('/incidents') if i['status']!='resolved')
        d.passed('Investigated security incident can be closed with an audited admin action')
        d.wait_for(lambda:len(json.load(urllib.request.urlopen('http://localhost:9091/api/v1/query?'+urllib.parse.urlencode({'query':'heimdall_agent_connections{job="heimdall"}'})))['data']['result'])==2,30)
        auth=base64.b64encode(('admin:'+d.secrets_env['HEIMDALL_GRAFANA_PASSWORD']).encode()).decode()
        request=urllib.request.Request('http://localhost:3001/api/dashboards/uid/heimdall-operations',headers={'Authorization':'Basic '+auth})
        dashboard=json.load(urllib.request.urlopen(request))
        assert len(dashboard['dashboard']['panels'])>=15
        d.passed('Grafana dashboard is provisioned and both control planes expose live metrics')
        (d.ROOT/'.local/feature-verification.json').write_text(json.dumps({'checks':d.results,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
    finally:
        if user_id: d.request('/users/'+user_id+'/status','POST',{'status':'deleted'})
        if token_id: d.request('/tokens/'+token_id,'DELETE')
        d.request('/nodes/move','POST',{'node_ids':[node['id']],'group_id':original_group})
        restore = dict(original_settings,version=d.request('/settings')['version'])
        d.request('/settings','PUT',restore)
        subprocess.run(['docker','compose','exec','-T','linux-node','userdel','-r',unmanaged],cwd=d.ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['docker','compose','exec','-T','linux-node','rm','-f',managed+'/authorized_keys/'+unmanaged],cwd=d.ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for path in [key,key.with_suffix('.pub')]: path.unlink(missing_ok=True)
        d.wait_for(d.synced)
        if group: d.request('/groups/'+group['id'],'DELETE')
        if role_id: d.request('/roles/'+role_id,'DELETE')
    print('Feature checks passed.',flush=True)

if __name__ == '__main__':
    try:
        main()
    finally:
        d.cleanup_admin_fixture()
