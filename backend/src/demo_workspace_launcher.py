from __future__ import annotations
import argparse, json, subprocess, sys
from demo_workspace import create, record, sanitize

def main():
    p=argparse.ArgumentParser(prog='demo-workspace',description='Per-SE container workspace launcher (workspace name is a selector, not authentication)')
    s=p.add_subparsers(dest='cmd',required=True)
    c=s.add_parser('create'); c.add_argument('se_name'); c.add_argument('--customer',default='')
    for n in ('status','stop','start'): q=s.add_parser(n); q.add_argument('se_name')
    a=p.parse_args(); name=sanitize(a.se_name); r=record(name,getattr(a,'customer',''))
    if a.cmd=='create': r=create(name,a.customer); print(json.dumps(r,indent=2)); print(f"Open through SSM port forwarding: local {r['port']} -> controller 127.0.0.1:{r['port']}"); return 0
    if a.cmd=='status':
        x=subprocess.run(['docker','inspect','-f','{{.State.Status}}',r['container']],text=True,capture_output=True); print((x.stdout.strip() or 'not-created')); print(json.dumps(r,indent=2)); return 0 if x.returncode==0 else 1
    subprocess.run(['docker',a.cmd,r['container']],check=True); return 0
if __name__=='__main__': raise SystemExit(main())
