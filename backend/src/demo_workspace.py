from __future__ import annotations
import hashlib, json, os, re, subprocess
from pathlib import Path

BASE = Path(os.environ.get('INFOBLOX_DEMO_USERS_ROOT','/var/lib/infoblox-nios-xaas-demo/users'))
REGISTRY = Path(os.environ.get('INFOBLOX_DEMO_REGISTRY','/var/lib/infoblox-nios-xaas-demo/workspaces.json'))
IMAGE = os.environ.get('INFOBLOX_DEMO_IMAGE','infoblox-nios-xaas-demo:2.1.0')
PORT_BASE = int(os.environ.get('INFOBLOX_DEMO_PORT_BASE','18000'))
PORT_SPAN = int(os.environ.get('INFOBLOX_DEMO_PORT_SPAN','1000'))

def sanitize(name:str)->str:
    s=re.sub(r'[^a-z0-9._-]+','-',name.strip().lower()).strip('-._')
    if not s or len(s)>48: raise ValueError('SE workspace name must be 1-48 safe characters')
    return s

def port_for(name:str)->int:
    n=int.from_bytes(hashlib.sha256(name.encode()).digest()[:4],'big')
    return PORT_BASE + (n % PORT_SPAN)

def mac_prefix_for(name:str)->str:
    d=bytearray(hashlib.sha256(name.encode()).digest()[:2])
    return f'02:{d[0]:02x}:{d[1]:02x}'

def record(name:str, customer:str='')->dict:
    name=sanitize(name); p=BASE/name
    return {'workspace':name,'customer':customer.strip(),'container':f'infoblox-demo-{name}',
            'path':str(p),'port':port_for(name),'mac_prefix':mac_prefix_for(name)}

def ensure_dirs(r):
    p=Path(r['path']); p.mkdir(parents=True,exist_ok=True); os.chmod(p,0o700)
    return p

def docker_args(r):
    return ['docker','run','-d','--name',r['container'],'--restart','unless-stopped',
            '--cap-drop','ALL','--cap-add','NET_RAW',
            '-p',f"127.0.0.1:{r['port']}:8787",'-v',f"{r['path']}:/workspace",
            '-e','INFOBLOX_DEMO_WORKSPACE=/workspace','-e',f"INFOBLOX_DEMO_OWNER={r['workspace']}",
            '-e',f"INFOBLOX_DEMO_CUSTOMER={r['customer']}",'-e',f"INFOBLOX_DEMO_DHCP_MAC_PREFIX={r['mac_prefix']}",
            IMAGE,'demo','web','foreground','--host','0.0.0.0','--port','8787']

def save_registry(r):
    REGISTRY.parent.mkdir(parents=True,exist_ok=True)
    try: data=json.loads(REGISTRY.read_text())
    except Exception: data={}
    data[r['workspace']]=r; REGISTRY.write_text(json.dumps(data,indent=2)+'\n'); os.chmod(REGISTRY,0o600)

def create(name,customer=''):
    r=record(name,customer); ensure_dirs(r)
    inspect=subprocess.run(['docker','inspect',r['container']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if inspect.returncode==0:
        subprocess.run(['docker','start',r['container']],check=True,stdout=subprocess.DEVNULL)
    else: subprocess.run(docker_args(r),check=True,stdout=subprocess.DEVNULL)
    save_registry(r); return r
