from __future__ import annotations
import json, os, requests
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from demo_workspace import create, get_record, list_records, sanitize, container_status

STATIC=Path(__file__).resolve().parent/'static'
PRODUCT='Infoblox NIOS-XaaS Demo'

def _target(name):
    r=get_record(name); return r, f"http://127.0.0.1:{r['port']}"

def _proxy(name, method, path, body=None, timeout=30):
    r,base=_target(name)
    if container_status(r)!='running': raise RuntimeError(f"Workspace {name} is not running")
    q=requests.request(method,base+path,json=body,timeout=timeout)
    try: payload=q.json()
    except Exception: payload={'error':q.text[:1000]}
    return q.status_code,payload

class H(BaseHTTPRequestHandler):
    def _json(self,obj,status=200):
        b=json.dumps(obj,default=str).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n=int(self.headers.get('Content-Length','0') or 0); return json.loads(self.rfile.read(n) or b'{}')
    def do_GET(self):
        p=urlparse(self.path).path
        if p=='/api/health': return self._json({'ok':True,'product':PRODUCT,'mode':'workspace-manager','bind':'localhost'})
        if p=='/api/workspaces': return self._json({'workspaces':list_records()})
        if p.startswith('/api/workspaces/') and p.endswith('/state'):
            name=sanitize(p.split('/')[3])
            try: code,data=_proxy(name,'GET','/api/state'); return self._json(data,code)
            except Exception as e: return self._json({'error':str(e)},503)
        if p=='/': p='/index.html'
        f=(STATIC/p.lstrip('/')).resolve()
        if STATIC not in f.parents or not f.exists(): self.send_error(404); return
        ct='text/html' if f.suffix=='.html' else 'text/css' if f.suffix=='.css' else 'application/javascript'
        b=f.read_bytes(); self.send_response(200); self.send_header('Content-Type',ct); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        p=urlparse(self.path).path
        try: body=self._body()
        except Exception as e: return self._json({'error':f'Invalid JSON: {e}'},400)
        if p=='/api/workspaces/open':
            try:
                name=sanitize(body.get('workspace','')); customer=str(body.get('customer','')).strip(); key=str(body.get('infoblox_api_key','')).strip()
                if not customer: return self._json({'error':'Customer / demo name is required'},400)
                if not key: return self._json({'error':'Infoblox API key is required'},400)
                r=create(name,customer)
                code,data=_proxy(name,'POST','/api/credentials',{'infoblox_api_key':key})
                if code>=400: return self._json(data,code)
                code,ready=_proxy(name,'POST','/api/readiness',{},timeout=90)
                if code>=400: return self._json(ready,code)
                _,state=_proxy(name,'GET','/api/state')
                return self._json({'workspace':r,'readiness':ready,'state':state})
            except Exception as e: return self._json({'error':str(e)},500)
        if p.startswith('/api/workspaces/'):
            parts=p.split('/'); name=sanitize(parts[3]); tail='/'+'/'.join(parts[4:])
            allowed={'/readiness','/run/deploy','/run/traffic','/run/cleanup','/job/stop','/credentials'}
            if tail not in allowed: return self._json({'error':'Unsupported workspace action'},404)
            try:
                code,data=_proxy(name,'POST','/api'+tail,body,timeout=90 if tail=='/readiness' else 30); return self._json(data,code)
            except Exception as e: return self._json({'error':str(e)},503)
        return self._json({'error':'Not found'},404)
    def log_message(self,*_): pass

def serve(host='127.0.0.1',port=8787):
    if host not in ('127.0.0.1','localhost','::1') and os.environ.get('INFOBLOX_DEMO_ALLOW_REMOTE_WEB')!='1': raise RuntimeError('Workspace Manager is localhost-only by default')
    print(f'{PRODUCT} Workspace Manager')
    print(f'Web UI: http://{host}:{port}')
    print('SE workflow is browser-only; Docker/CLI commands are admin/debug operations.')
    ThreadingHTTPServer((host,port),H).serve_forever()
