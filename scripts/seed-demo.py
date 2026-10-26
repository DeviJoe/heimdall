#!/usr/bin/env python3
"""Create one persistent demonstrator with a local SSH key; never overwrite credentials."""
import importlib.util, json, os, pathlib, secrets, subprocess

spec=importlib.util.spec_from_file_location('demo',__file__.replace('seed-demo.py','check-demo.py'))
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)

def main():
    d.wait_for(lambda:d.login_admin())
    if any(u['login']=='operator' for u in d.request('/users')):
        operator=next(u for u in d.request('/users') if u['login']=='operator')
        keys=d.request('/users/'+operator['id']+'/keys')
        if not any(k['status']=='active' for k in keys):
            key=d.ROOT/'.local'/('operator_ed25519_'+secrets.token_hex(4))
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
            d.request('/users/'+operator['id']+'/keys','POST',{'name':'Ключ Compose-стенда','public_key':key.with_suffix('.pub').read_text()},expected=201)
            credentials=d.ROOT/'.local/operator-credentials.json'
            saved=json.loads(credentials.read_text())
            saved['ssh_private_key']=str(key)
            credentials.write_text(json.dumps(saved,indent=2));credentials.chmod(0o600)
            d.wait_for(d.synced)
            print('Demo SSH key rotated after expiry; web credentials retained.')
        else:
            print('Demo operator already exists; credentials retained.')
    else:
        group=next(g for g in d.request('/groups') if g['name']=='Demo Linux')
        role=next(r for r in d.request('/roles') if r['name']=='Linux operator')
        created=d.request('/users','POST',{'login':'operator','display_name':'Демо-оператор'},expected=201)
        uid=created['user']['id'];password='Demo-'+secrets.token_urlsafe(20);admin_cookies=list(d.jar);d.jar.clear()
        d.request('/auth/invitation','POST',{'token':created['invitation_url'].split('#')[1],'password':password})
        key=d.ROOT/'.local/operator_ed25519'
        if not key.exists():subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
        d.request('/users/'+uid+'/keys','POST',{'name':'Ключ Compose-стенда','public_key':key.with_suffix('.pub').read_text()},expected=201)
        d.jar.clear()
        for cookie in admin_cookies:d.jar.set_cookie(cookie)
        d.request('/bindings','POST',{'user_id':uid,'role_id':role['id'],'group_id':group['id']})
        d.wait_for(d.synced)
        credentials=d.ROOT/'.local/operator-credentials.json'
        credentials.write_text(json.dumps({'login':'operator','web_password':password,'ssh_private_key':str(key)},indent=2))
        os.chmod(credentials,0o600)
        print('Demo operator created. Credentials: .local/operator-credentials.json (0600).')

    # A small persistent fleet makes group membership and inherited access visible.
    groups=d.request('/groups');root=next(g for g in groups if g['name']=='Demo Linux')
    for name in ['Staging','Production']:
     if not any(g['name']==name for g in groups):
      d.request('/groups','POST',{'name':name,'parent_id':root['id']})
    groups=d.request('/groups');nodes=d.request('/nodes')
    for node in nodes:
     target={'linux-stage':'Staging','linux-web':'Production','linux-db':'Production'}.get(node['name'])
     if target:
      group_id=next(g['id'] for g in groups if g['name']==target)
      if node['group_id']!=group_id:d.request('/nodes/move','POST',{'node_ids':[node['id']],'group_id':group_id})

    # Persistent examples for the UNIX directory and scoped service-account inventory.
    # Existing credentials, enrollment policies and user-created resources are retained.
    operator=next(u for u in d.request('/users?query=operator') if u['login']=='operator')
    def named(resource,name):
     return next((item for item in d.request(resource+'?query='+__import__('urllib.parse',fromlist=['quote']).quote(name)) if item['name']==name),None)
    def unix_group(name,user):
     group=named('/unix-groups',name)
     if not group:
      d.request('/unix-groups','POST',{'name':name,'gid':0,'members':[user['id']]})
      group=named('/unix-groups',name)
     else:
      memberships=d.request('/users/'+user['id']+'/unix-groups')
      if not any(g['id']==group['id'] for g in memberships):d.request('/unix-groups/'+group['id']+'/members','POST',{'add':[user['id']],'remove':[]})
     return group
    native=named('/roles','Demo UNIX operator')
    if not native:
     d.request('/roles','POST',{'name':'Demo UNIX operator','permissions':[],'linux_access':True,'sudo':[],'sudoers':'ALL=(root) NOPASSWD: /usr/bin/id ""\nALL=(root) NOPASSWD: /usr/bin/whoami ""'})
     native=named('/roles','Demo UNIX operator')
    operators=unix_group('demo_operators',operator)
    assignments=d.request('/unix-assignments')
    if not any(b['unix_group_id']==operators['id'] and b['group_id']==root['id'] and b['role_id']==native['id'] for b in assignments):
     d.request('/unix-assignments','POST',{'unix_group_id':operators['id'],'group_id':root['id'],'role_id':native['id']})
    people=named('/user-groups','Demo engineers')
    if not people:
     d.request('/user-groups','POST',{'name':'Demo engineers','mfa_policy':'none','purpose':'general','members':[operator['id']]})

    service=next((u for u in d.request('/users?query=demo_ansible&kind=service') if u['login']=='demo_ansible'),None)
    if not service:
     service=d.request('/users','POST',{'login':'demo_ansible','display_name':'Ansible · demo','kind':'service'},expected=201)['user']
    automation=unix_group('demo_automation',service)
    plain=named('/roles','Linux user')
    if not any(b['unix_group_id']==automation['id'] and b['group_id']==root['id'] and b['role_id']==plain['id'] for b in assignments):
     d.request('/unix-assignments','POST',{'unix_group_id':automation['id'],'group_id':root['id'],'role_id':plain['id']})
    inventory=named('/roles','Inventory reader')
    if not inventory:
     d.request('/roles','POST',{'name':'Inventory reader','permissions':['inventory.read'],'linux_access':False,'sudo':[]})
     inventory=named('/roles','Inventory reader')
    if not any(b['role_id']==inventory['id'] and b['group_id']==root['id'] for b in d.request('/users/'+service['id']+'/bindings')):
     d.request('/bindings','POST',{'user_id':service['id'],'role_id':inventory['id'],'group_id':root['id']})
    print('Demo UNIX directory and scoped Ansible service account prepared.')

if __name__ == '__main__':
    d.lock_stand()
    try:
        main()
    finally:
        d.cleanup_admin_fixture()
