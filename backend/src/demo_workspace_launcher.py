from __future__ import annotations
import argparse, json, subprocess
from demo_workspace import create, get_record, sanitize, start, stop, container_status, list_records


def main():
    p=argparse.ArgumentParser(prog='demo-workspace',description='Admin/debug workspace launcher. SEs normally use the browser UI.')
    s=p.add_subparsers(dest='cmd',required=True)
    c=s.add_parser('create'); c.add_argument('se_name'); c.add_argument('--customer',default='')
    for n in ('status','stop','start'): q=s.add_parser(n); q.add_argument('se_name')
    s.add_parser('list')
    a=p.parse_args()
    if a.cmd=='list': print(json.dumps(list_records(),indent=2)); return 0
    name=sanitize(a.se_name)
    if a.cmd=='create': r=create(name,a.customer); print(json.dumps(r,indent=2)); return 0
    if a.cmd=='status': r=get_record(name); r['status']=container_status(r); print(json.dumps(r,indent=2)); return 0
    r=start(name) if a.cmd=='start' else stop(name); print(json.dumps(r,indent=2)); return 0

if __name__=='__main__': raise SystemExit(main())
