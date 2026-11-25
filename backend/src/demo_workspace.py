from __future__ import annotations
import hashlib, json, os, re, subprocess, time
from pathlib import Path
import requests

BASE = Path(os.environ.get('INFOBLOX_DEMO_USERS_ROOT','/var/lib/infoblox-nios-xaas-demo/users'))
REGISTRY = Path(os.environ.get('INFOBLOX_DEMO_REGISTRY','/var/lib/infoblox-nios-xaas-demo/workspaces.json'))
IMAGE = os.environ.get('INFOBLOX_DEMO_IMAGE','infoblox-nios-xaas-demo:2.2.0')
PORT_BASE = int(os.environ.get('INFOBLOX_DEMO_PORT_BASE','18000'))
PORT_SPAN = int(os.environ.get('INFOBLOX_DEMO_PORT_SPAN','1000'))
SOURCE_ROOT = Path(os.environ.get('INFOBLOX_DEMO_SOURCE_ROOT', str(Path(__file__).resolve().parents[2])))


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


def image_exists()->bool:
    return subprocess.run(['docker','image','inspect',IMAGE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0


def ensure_image():
    if image_exists(): return
    dockerfile=SOURCE_ROOT/'Dockerfile'
    if not dockerfile.exists(): raise RuntimeError(f'Docker image {IMAGE} is missing and Dockerfile was not found at {dockerfile}')
    subprocess.run(['docker','build','-t',IMAGE,str(SOURCE_ROOT)],check=True)


def docker_args(r):
    return ['docker','run','-d','--name',r['container'],'--restart','unless-stopped',
            '--cap-drop','ALL','--cap-add','NET_RAW',
            '-p',f"127.0.0.1:{r['port']}:8787",'-v',f"{r['path']}:/workspace",
            '-e','INFOBLOX_DEMO_WORKSPACE=/workspace','-e',f"INFOBLOX_DEMO_OWNER={r['workspace']}",
            '-e',f"INFOBLOX_DEMO_CUSTOMER={r['customer']}",'-e',f"INFOBLOX_DEMO_DHCP_MAC_PREFIX={r['mac_prefix']}",
            IMAGE,'demo','web','foreground','--host','0.0.0.0','--port','8787']


def _registry_data():
    try: return json.loads(REGISTRY.read_text())
    except Exception: return {}


def save_registry(r):
    REGISTRY.parent.mkdir(parents=True,exist_ok=True)
    data=_registry_data(); data[r['workspace']]=r
    REGISTRY.write_text(json.dumps(data,indent=2)+'\n'); os.chmod(REGISTRY,0o600)


def get_record(name):
    name=sanitize(name); data=_registry_data()
    return data.get(name) or record(name)


def container_status(r):
    x=subprocess.run(['docker','inspect','-f','{{.State.Status}}',r['container']],text=True,capture_output=True)
    return (x.stdout.strip() if x.returncode==0 else 'not-created') or 'unknown'


def wait_health(r, timeout=45):
    url=f"http://127.0.0.1:{r['port']}/api/health"; end=time.time()+timeout; last=''
    while time.time()<end:
        try:
            q=requests.get(url,timeout=2)
            if q.ok: return q.json()
            last=f'HTTP {q.status_code}'
        except requests.RequestException as e: last=str(e)
        time.sleep(1)
    raise RuntimeError(f'Workspace container started but web health did not become ready: {last}')


def create(name,customer='', build_if_missing=True):
    r=record(name,customer); ensure_dirs(r)
    if build_if_missing: ensure_image()
    inspect=subprocess.run(['docker','inspect',r['container']],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if inspect.returncode==0:
        # Existing container keeps its original env/customer. Recreate only when customer label changed.
        old=get_record(name)
        if customer and old.get('customer') != customer:
            subprocess.run(['docker','rm','-f',r['container']],check=True,stdout=subprocess.DEVNULL)
            subprocess.run(docker_args(r),check=True,stdout=subprocess.DEVNULL)
        else:
            subprocess.run(['docker','start',r['container']],check=False,stdout=subprocess.DEVNULL)
            r['customer']=old.get('customer') or customer
    else:
        subprocess.run(docker_args(r),check=True,stdout=subprocess.DEVNULL)
    save_registry(r); health=wait_health(r); r['health']=health; r['status']='running'; return r


def stop(name):
    r=get_record(name); subprocess.run(['docker','stop',r['container']],check=True,stdout=subprocess.DEVNULL); return r


def start(name):
    r=get_record(name); subprocess.run(['docker','start',r['container']],check=True,stdout=subprocess.DEVNULL); wait_health(r); return r


def list_records():
    data=_registry_data(); out=[]
    for name,r in sorted(data.items()):
        x=dict(r); x['status']=container_status(x); out.append(x)
    return out
