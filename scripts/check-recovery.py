#!/usr/bin/env python3
"""Additional fault and authentication checks on the isolated Heimdall demo node."""
import base64, hashlib, hmac, importlib.util, json, secrets, struct, time, subprocess

spec = importlib.util.spec_from_file_location('demo', __file__.replace('check-recovery.py', 'check-demo.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

def totp(secret):
    raw = base64.b32decode(secret + '=' * ((8-len(secret)%8)%8))
    digest = hmac.new(raw, struct.pack('>Q', int(time.time())//30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return f'{(struct.unpack(">I", digest[offset:offset+4])[0]&0x7fffffff)%1000000:06d}'

def admin():
    d.jar.clear()
    d.login_admin()

def sql(statement):
    return d.compose('exec','-T','postgres','psql','-U','linpam','-d','linpam','-At','-c',statement)

def main():
    d.lock_stand()
    admin()
    group = next(g for g in d.request('/groups') if g['name']=='Demo Linux')
    role = next(r for r in d.request('/roles') if r['name']=='Linux operator')
    login = 'recover_'+secrets.token_hex(3)
    created = d.request('/users','POST',{'login':login,'display_name':'Recovery verification','require_mfa':True},expected=201)
    user_id = created['user']['id']
    password = 'Check-'+secrets.token_urlsafe(20)
    d.request('/bindings','POST',{'user_id':user_id,'role_id':role['id'],'group_id':group['id']})
    d.jar.clear()
    d.request('/auth/invitation','POST',{'token':created['invitation_url'].split('#')[1],'password':password})
    assert d.request('/me')['principal']['restricted']
    d.request('/users/'+user_id+'/linux-password','PUT',{'password':password},expected=403)
    factor = d.request('/me/totp/begin','POST',{})
    completed = d.request('/me/totp/finish','POST',{'code':totp(factor['secret'])})
    codes = completed['recovery_codes']
    assert len(codes)==10 and not d.request('/me')['principal']['restricted']
    d.request('/auth/logout','POST',{})
    challenge = d.request('/auth/login','POST',{'login':login,'password':password})['challenge']
    d.request('/auth/totp','POST',{'challenge':challenge,'code':totp(factor['secret'])},expected=401)
    d.request('/auth/totp','POST',{'challenge':challenge,'code':codes[0]})
    d.request('/auth/logout','POST',{})
    challenge = d.request('/auth/login','POST',{'login':login,'password':password})['challenge']
    d.request('/auth/totp','POST',{'challenge':challenge,'code':codes[0]},expected=401)
    d.request('/auth/totp','POST',{'challenge':challenge,'code':codes[1]})
    d.passed('Required MFA onboarding, TOTP replay rejection and one-use recovery codes')
    admin()
    d.wait_for(d.synced)
    node = next(n for n in d.request('/nodes') if n['name']=='linux-demo' and not n['disabled'])
    # A missing CP ACK must not strand a node with a newer durable checkpoint.
    sql("UPDATE nodes SET applied_revision=greatest(applied_revision-1,0),status='pending' WHERE id='"+node['id']+"'")
    d.compose('restart','linux-node')
    d.wait_for(d.synced)
    d.passed('Lost ACK recovers through a full snapshot without losing local accounts')
    recovery = d.request('/nodes/'+node['id']+'/recovery-token','POST',{})
    def recover():
        return subprocess.run(['docker','compose','exec','-T','--user','998:998','linux-node','sh','-c','read -r HEIMDALL_RECOVERY_TOKEN; export HEIMDALL_RECOVERY_TOKEN; exec heimdall-agent -recover'],cwd=d.ROOT,input=recovery['token']+'\n',capture_output=True,text=True)
    assert recover().returncode==0
    assert recover().returncode!=0
    d.wait_for(d.synced)
    d.passed('Node-bound recovery token replaces certificate once and preserves node identity')
    d.compose('exec','-T','linux-node','sh','-c',f'printf preserved > /home/{login}/migration-proof; chown {created["user"]["uid"]}:{created["user"]["gid"]} /home/{login}/migration-proof')
    d.request('/users/'+user_id+'/status','POST',{'status':'disabled'})
    d.wait_for(d.synced)
    user = next(u for u in d.request('/users') if u['id']==user_id)
    new_login=login+'_m'
    new_uid=500000+secrets.randbelow(100000)
    user.update(login=new_login,uid=new_uid,gid=new_uid,home='/home/'+new_login,maintenance=True)
    d.request('/users/'+user_id,'PUT',user)
    d.wait_for(d.synced)
    output=d.compose('exec','-T','linux-node','sh','-c',f'getent passwd {new_login}; stat -c "%u:%g" /home/{new_login}/migration-proof; cat /home/{new_login}/migration-proof')
    assert f'{new_uid}:{new_uid}' in output and output.rstrip().endswith('preserved')
    d.passed('Confirmed disabled POSIX migration preserves home contents and changes ownership')
    # Inject a symlink at a managed file: root helper must reject it and report failure.
    target=d.managed_directory()+'/authorized_keys/'+new_login
    d.compose('exec','-T','linux-node','sh','-c',f'rm {target}; ln -s /tmp/linpam-drift-test {target}')
    try:
        d.wait_for(lambda:any(n['status']=='failed' for n in d.request('/nodes')),100)
        d.wait_for(lambda:any(i['kind']=='apply_failed' and i['status']!='resolved' for i in d.request('/incidents')),20)
        d.passed('Local drift failure is visible after ACK and creates a critical incident')
    finally:
        d.compose('exec','-T','linux-node','rm',target)
    d.wait_for(d.synced,100)
    d.compose('exec','-T','linux-node','sh','-c',f'test -f {target} && test ! -L {target} && test ! -s {target}')
    d.passed('Root-owned approved state repairs drift and clears the failed state')
    d.request('/users/'+user_id+'/status','POST',{'status':'deleted'})
    d.wait_for(d.synced)
    (d.ROOT/'.local/recovery-verification.json').write_text(json.dumps({'checks':d.results,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
    print('Additional recovery checks passed.',flush=True)

if __name__ == '__main__':
    try:
        main()
    finally:
        d.cleanup_admin_fixture()
