#!/usr/bin/env python3
"""Fresh native node: root enrollment binding, signed apply and durable checkpoint."""
import importlib.util, json, os, pathlib, subprocess, time, uuid, secrets
spec=importlib.util.spec_from_file_location('demo',pathlib.Path(__file__).with_name('check-demo.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
def main():
 d.lock_stand()
 d.login_admin()
 group=next(g for g in d.request('/groups') if g['name']=='Demo Linux')
 token=d.request('/join-tokens','POST',{'group_id':group['id'],'max_uses':1,'ttl_seconds':300})['token']
 env=dict(os.environ,HEIMDALL_ACCEPTANCE_JOIN_TOKEN=token)
 def compose(*args):
  return subprocess.run(['docker','compose','-f','compose.yaml','-f','compose.test.yaml',*args],cwd=d.ROOT,env=env,capture_output=True,text=True,check=True).stdout
 node=None
 user=None
 binding=None
 key=d.ROOT/'.local'/('unix-key-'+secrets.token_hex(4))
 suffix=secrets.token_hex(4)
 try:
  compose('up','-d','--build','enrollment-node')
  node=d.wait_for(lambda:next((n for n in d.request('/nodes') if n['name']=='enrollment-acceptance' and not n['disabled'] and n['status']=='in_sync'),None),90)
  checkpoint=json.loads(compose('exec','-T','enrollment-node','cat','/var/lib/heimdall-helper/checkpoint.json'))
  pin=json.loads(compose('exec','-T','enrollment-node','cat','/var/lib/heimdall-helper/bootstrap.json'))
  assert checkpoint['node_id']==node['id'] and checkpoint['revision']==node['applied_revision']
  assert len(pin['nonce'])==64 and len(pin['token_hash'])==64
  d.passed('Fresh native enrollment pins root intent and applies a signed node-bound manifest')
  # The same real Linux fixture exercises UNIX group grants and reductions.
  user=d.request('/users','POST',{'login':'unix_'+suffix,'kind':'service','display_name':'UNIX regression'},expected=201)['user']
  subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
  public=key.with_suffix('.pub').read_text()
  d.request('/users/'+user['id']+'/keys','POST',{'name':'Native regression','public_key':public},expected=201)
  d.request('/unix-groups','POST',{'name':'eng_'+suffix,'gid':0,'members':[user['id']]})
  unix_group=next(g for g in d.request('/unix-groups') if g['name']=='eng_'+suffix)
  d.request('/roles','POST',{'name':'Native sudo '+suffix,'permissions':['*'],'linux_access':True,'sudo':[],'sudoers':'ALL=(root:root) NOPASSWD: /usr/bin/id *'})
  role=next(r for r in d.request('/roles') if r['name']=='Native sudo '+suffix)
  d.request('/unix-assignments','POST',{'unix_group_id':unix_group['id'],'group_id':group['id'],'role_id':role['id']})
  binding=next(b for b in d.request('/unix-assignments') if b['unix_group_id']==unix_group['id'])
  d.wait_for(d.synced)
  assert unix_group['name'] in compose('exec','-T','enrollment-node','id',user['login'])
  assert d.ssh(user['login'],key,'sudo -n /usr/bin/id -u').strip()=='0'
  d.passed('Named UNIX group and native sudoers wildcard apply through group assignment')
  # Label only the disposable child node, preserving access on the main demo.
  child=d.request('/groups','POST',{'name':'Label regression '+suffix,'parent_id':group['id']})['group']
  d.request('/nodes/move','POST',{'node_ids':[node['id']],'group_id':child['id']})
  node['group_id']=child['id']
  d.request('/security/labels','POST',{'resource_type':'node_group','resource_id':child['id'],'label':{'level':2,'categories':['production']}})
  d.wait_for(d.synced)
  managed='/etc/heimdall'
  assert not compose('exec','-T','enrollment-node','cat',managed+'/authorized_keys/'+user['login']).strip()
  d.request('/security/labels','POST',{'resource_type':'user','resource_id':user['id'],'label':{'level':3,'categories':['production']}})
  d.wait_for(d.synced)
  assert public.strip() in compose('exec','-T','enrollment-node','cat',managed+'/authorized_keys/'+user['login'])
  d.passed('Mandatory level/category denies broad role and grants only matching clearance')
  d.request('/unix-assignments/'+binding['id'],'DELETE')
  binding=None
  unix_group=role=child=None
  d.wait_for(d.synced)
  d.ssh(user['login'],key,'id',success=False)
  assert unix_group['name'] not in compose('exec','-T','enrollment-node','id',user['login'])
  assert not compose('exec','-T','enrollment-node','cat',managed+'/authorized_keys/'+user['login']).strip()
  d.passed('UNIX assignment removal locks the account, clears keys/sudo and supplementary membership')
  current=d.request('/users?query='+user['login'])[0]
  d.request('/users/'+user['id'],'PUT',dict(current,require_sk=True,maintenance=False))
  d.request('/users/'+user['id']+'/keys','POST',{'name':'Software forbidden','public_key':public},expected=400)
  d.passed('Per-user SK policy rejects software keys through the API')

  (d.ROOT/'.local/enrollment-verification.json').write_text(json.dumps({'checks':d.results,'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())},indent=2))
 finally:
  if binding:
   d.request('/unix-assignments/'+binding['id'],'DELETE')
  if user:
   d.request('/users/'+user['id']+'/status','POST',{'status':'deleted'})
   d.wait_for(d.synced)
  for path in (key,key.with_suffix('.pub')):path.unlink(missing_ok=True)
  if node: d.request('/nodes/'+node['id'],'PUT',{'group_id':node['group_id'],'disabled':True})
  compose('rm','-s','-f','enrollment-node')
  if node:
   d.cleanup_ephemeral_node(node,'enrollment-acceptance')
  if child: d.request('/groups/'+child['id'],'DELETE')
  if role: d.request('/roles/'+role['id'],'DELETE')
  if unix_group: d.request('/unix-groups/'+unix_group['id'],'DELETE')
 print('Enrollment checks passed.',flush=True)
if __name__ == '__main__':
    try:
        main()
    finally:
        d.cleanup_admin_fixture()
