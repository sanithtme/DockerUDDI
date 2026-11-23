#!/usr/bin/env python3
"""Generate synthetic DHCP clients and optionally request leases through the project's DRAS provider.
These clients are deliberately separate from Asset Insights inventory.
"""
import argparse, json, subprocess, time
from pathlib import Path

def mac_for(i, prefix):
    base=[int(x,16) for x in prefix.split(':')]
    if len(base)!=3: raise ValueError('prefix must be 3 bytes, e.g. 02:dd:10')
    n=i & 0xffffff
    return ':'.join(f'{x:02x}' for x in base+[(n>>16)&255,(n>>8)&255,n&255])

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--count',type=int,default=10)
    p.add_argument('--mac-prefix',default='02:dd:10')
    p.add_argument('--hostname-prefix',default='demo-dhcp')
    p.add_argument('--server',required=True)
    p.add_argument('--relay',required=True)
    p.add_argument('--dras',default='dras')
    p.add_argument('--lease-dir',default='state/dhcp-synthetic')
    p.add_argument('--delay',type=float,default=.5)
    p.add_argument('--dry-run',action='store_true')
    a=p.parse_args(); out=Path(a.lease_dir); out.mkdir(parents=True,exist_ok=True)
    clients=[]
    for i in range(1,a.count+1):
        mac=mac_for(i,a.mac_prefix); host=f'{a.hostname_prefix}-{i:04d}'; lease=out/f'{host}.lease'
        cmd=[a.dras,'-i',a.server,'-c',a.relay,'-a',mac,'-O',f'12:{host.encode().hex()}','-o',str(lease),'-v']
        print(' '.join(cmd)); rc=None
        if not a.dry_run:
            rc=subprocess.run(cmd).returncode; time.sleep(a.delay)
        clients.append({'id':host,'hostname':host,'mac':mac,'lease_file':str(lease),'returncode':rc})
    (out/'clients.json').write_text(json.dumps({'clients':clients},indent=2))
    print(f'wrote {out / "clients.json"}')
if __name__=='__main__': main()
