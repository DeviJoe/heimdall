#!/usr/bin/env python3
"""Ansible script inventory: current token/RBAC checked on every invocation."""
import argparse, json, os, ssl, sys, urllib.request

def main():
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--list', action='store_true')
    action.add_argument('--host')
    args = parser.parse_args()
    base = os.environ['HEIMDALL_URL'].rstrip('/')
    if not base.startswith('https://'):
        raise ValueError('HEIMDALL_URL must use HTTPS')
    request = urllib.request.Request(base + '/api/v1/ansible/inventory', headers={'Authorization': 'Bearer ' + os.environ['HEIMDALL_API_TOKEN']})
    context = ssl.create_default_context(cafile=os.environ.get('HEIMDALL_CA_FILE'))
    with urllib.request.urlopen(request, context=context, timeout=20) as response:
        inventory = json.load(response)
    print(json.dumps(inventory if args.list else inventory['_meta']['hostvars'].get(args.host, {})))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Heimdall inventory failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
