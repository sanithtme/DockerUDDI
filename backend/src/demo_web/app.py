from __future__ import annotations
import json, os, signal, subprocess, sys, threading, time, uuid, requests
import yaml
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from demo_identity import identity, secure_workspace
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = Path(os.environ.get("INFOBLOX_DEMO_WORKSPACE", str(Path.home()/".infoblox-demo"))).expanduser().resolve()
STATIC = Path(__file__).resolve().parent / "static"
JOBS = WORKSPACE / "web-jobs"
_lock = threading.Lock()
_current = None
_session_api_key = None
_readiness = None

def _active_state():
    d=WORKSPACE/"deployment"/"deployment-state"
    states=[]
    if d.exists():
        for p in d.glob("*.json"):
            try:
                x=json.loads(p.read_text()); x["_mtime"]=p.stat().st_mtime
                if x.get("phase") != "cleaned": states.append(x)
            except Exception: pass
    states.sort(key=lambda x:x.get("_mtime",0), reverse=True)
    return states[0] if states else None

def _job_dict(job):
    if not job: return None
    p=job.get("proc")
    running=p is not None and p.poll() is None
    log=Path(job["log"])
    tail=[]
    if log.exists(): tail=log.read_text(errors="replace").splitlines()[-80:]
    return {"id":job["id"],"action":job["action"],"running":running,"returncode":None if running else (p.poll() if p else job.get("returncode")),"started":job["started"],"elapsed":int(time.time()-job["started"]),"log_tail":tail}

def _env():
    env=os.environ.copy(); env["INFOBLOX_DEMO_WORKSPACE"]=str(WORKSPACE); env["INFOBLOX_DEMO_OWNER"]=identity(); env["PYTHONUNBUFFERED"]="1"
    if _session_api_key: env["INFOBLOX_API_KEY"]=_session_api_key
    return env

def _config():
    p=WORKSPACE/"config.yaml"
    if not p.exists(): return {}
    try: return yaml.safe_load(p.read_text()) or {}
    except Exception: return {}

def _check(name, scope, ok, detail, action=""):
    return {"name":name,"scope":scope,"ok":ok if ok is None else bool(ok),"detail":detail,"action":action}

def _probe(method, base, path, key, *, json_body=None, params=None, timeout=12):
    url=base.rstrip("/")+path
    headers={"Authorization":f"Token {key}","Accept":"application/json","Content-Type":"application/json"}
    try:
        r=requests.request(method,url,headers=headers,json=json_body,params=params,timeout=timeout)
        if r.status_code in (401,403): return False, f"HTTP {r.status_code}: authentication/entitlement denied"
        if r.status_code==404: return False, "API capability not found for this tenant"
        if not r.ok: return False, f"HTTP {r.status_code}: {r.text[:180]}"
        return True, "Available"
    except requests.RequestException as e:
        return False, f"Connectivity/API error: {e}"

def _reconcile_state(st, cfg, key):
    if not st: return {"state":"none","verified":True,"detail":"No local active deployment record"}
    depid=st.get("deployment_id")
    # Verify the AWS resources recorded in the checkpoint without modifying them.
    aws_ok=False; aws_detail="No AWS resource IDs recorded"
    try:
        import boto3
        ec2=boto3.client("ec2",region_name=st.get("region") or cfg.get("platform",{}).get("region"))
        ids=st.get("vpn_connection_ids") or []
        if ids:
            got=ec2.describe_vpn_connections(VpnConnectionIds=ids).get("VpnConnections",[])
            aws_ok=len(got)==len(ids); aws_detail=f"{len(got)}/{len(ids)} recorded VPN connections found"
        elif st.get("client_instance_id"):
            got=ec2.describe_instances(InstanceIds=[st["client_instance_id"]]).get("Reservations",[])
            aws_ok=bool(got); aws_detail="Recorded client instance found" if got else "Recorded client instance not found"
    except Exception as e:
        aws_detail=f"AWS reconciliation failed: {e}"
    # Verify that the CSP endpoint belongs to this deployment.
    inf=cfg.get("infoblox",{}); base=inf.get("base_url","https://csp.infoblox.com")
    csp_ok=False; csp_detail="Not verified"
    try:
        r=requests.get(base.rstrip("/")+"/api/universalinfra/v1/endpoints/",headers={"Authorization":f"{inf.get('auth_scheme','Token')} {key}","Accept":"application/json"},timeout=12)
        if r.ok:
            ep=(r.json() or {}).get("result") or {}
            expected=f"Infoblox-Sales-{''.join(c if c.isalnum() or c in '._-' else '-' for c in depid)[:48]}-Endpoint"
            tags=ep.get("tags") or {}
            csp_ok=ep.get("name")==expected or str(tags.get("deployment-id") or tags.get("DeploymentId") or "")==depid
            csp_detail="Owned CSP endpoint found" if csp_ok else "CSP endpoint is absent or belongs to another deployment"
        else: csp_detail=f"CSP verification HTTP {r.status_code}"
    except requests.RequestException as e:
        csp_detail=f"CSP verification failed: {e}"
    if aws_ok and csp_ok: return {"state":"verified","verified":True,"detail":f"{aws_detail}; {csp_detail}"}
    if not aws_ok and not csp_ok: return {"state":"stale","verified":True,"detail":f"{aws_detail}; {csp_detail}"}
    return {"state":"partial","verified":True,"detail":f"{aws_detail}; {csp_detail}"}

def run_readiness():
    global _readiness
    checks=[]; cfg=_config(); key=_session_api_key or os.environ.get("INFOBLOX_API_KEY")
    try:
        secure_workspace(create=True); checks.append(_check("Controller workspace","deployment",True,f"Isolated workspace for {identity()}"))
    except Exception as e:
        checks.append(_check("Controller workspace","deployment",False,str(e),"Use SSM Run As / a unique Linux user and correct workspace ownership"))
    if not key:
        checks.append(_check("Infoblox authentication","deployment",False,"API credential missing","Enter the API key for this web session"))
        _readiness={"checked_at":time.time(),"deployment_ready":False,"traffic_ready":False,"traffic_verified":False,"checks":checks,"reconciliation":{"state":"unverified","verified":False,"detail":"Credential required"}}
        return _readiness
    cfg_inf=cfg.get("infoblox",{}); base=cfg_inf.get("base_url","https://csp.infoblox.com")
    probes=[
      ("NIOS-XaaS","deployment","GET","/api/universalinfra/v1/endpoints/",None,None),
      ("Threat Defense","deployment","GET","/api/atcfw/v1/security_policies",None,{"_fields":"id,name,is_default"}),
      ("DNS","deployment","GET","/api/ddi/v1/dns/view",None,{"_limit":1}),
      ("DHCP / IPAM","deployment","GET","/api/ddi/v1/ipam/ip_space",None,{"_limit":1}),
      ("Asset Insights","traffic","POST","/api/v1/assets/search",{"page_size":1,"sync":{"mode":"FULL"}},None),
      ("TIDE","traffic","GET","/tide/api/data/threats/state",None,{"type":"host","rlimit":1,"data_format":"json"}),
    ]
    auth_ok,auth_detail=_probe("GET",base,"/api/universalinfra/v1/endpoints/",key)
    checks.append(_check("Infoblox authentication","deployment",auth_ok,"Authenticated" if auth_ok else auth_detail,"Verify the API key and tenant access"))
    if auth_ok:
        for name,scope,method,path,body,params in probes:
            ok,detail=_probe(method,base,path,key,json_body=body,params=params)
            checks.append(_check(name,scope,ok,detail,f"Verify {name} entitlement/API access for this tenant"))
    else:
        for name,scope,*_ in probes: checks.append(_check(name,scope,None,"Not checked because authentication failed","Validate Infoblox authentication first"))
    # AWS/control-plane probe remains read-only/validation oriented through the existing doctor path.
    control_ok=False; detail="Not tested"
    try:
        cp=subprocess.run([sys.executable,"-c","import sys; from demo_launcher import main; sys.exit(main())","readiness"],cwd=str(WORKSPACE),env=_env(),capture_output=True,text=True,timeout=45)
        detail=(cp.stdout+"\n"+cp.stderr).strip()[-700:] or "Control-plane probe completed"; control_ok=cp.returncode==0
    except subprocess.TimeoutExpired: detail="AWS/control-plane probe timed out"
    checks.append(_check("AWS deployment access","deployment",control_ok,"Available" if control_ok else detail,"Verify controller IAM role and AWS connectivity"))
    dep_ok=all(c.get("ok") is True for c in checks if c["scope"]=="deployment")
    traffic_verified=all(c.get("ok") is True for c in checks if c["scope"]=="traffic")
    rec=_reconcile_state(_active_state(),cfg,key) if auth_ok else {"state":"unverified","verified":False,"detail":"Credential required"}
    _readiness={"checked_at":time.time(),"deployment_ready":dep_ok,"traffic_ready":dep_ok and traffic_verified,"traffic_verified":traffic_verified,"checks":checks,"reconciliation":rec}
    return _readiness

def start_job(action, args=None):
    global _current
    args=args or []
    with _lock:
        if _current and _current.get("proc") and _current["proc"].poll() is None:
            raise RuntimeError("Another demo operation is already running")
        JOBS.mkdir(parents=True,exist_ok=True)
        jid=str(uuid.uuid4())[:8]; log=JOBS/f"{jid}.log"
        cmd=[sys.executable,"-c","import sys; from demo_launcher import main; sys.exit(main())",action,*args]
        env=_env()
        f=log.open("w",buffering=1)
        p=subprocess.Popen(cmd,cwd=str(WORKSPACE),env=env,stdout=f,stderr=subprocess.STDOUT,text=True,start_new_session=True)
        _current={"id":jid,"action":action,"proc":p,"started":time.time(),"log":str(log),"file":f}
        return _job_dict(_current)

def stop_job():
    global _current
    with _lock:
        if not _current or not _current.get("proc") or _current["proc"].poll() is not None: return False
        os.killpg(_current["proc"].pid, signal.SIGINT); return True

class H(BaseHTTPRequestHandler):
    def _json(self,obj,status=200):
        b=json.dumps(obj,default=str).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def _body(self):
        n=int(self.headers.get("Content-Length","0") or 0); return json.loads(self.rfile.read(n) or b"{}")
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/api/health": return self._json({"ok":True,"bind":"localhost","product":"Infoblox NIOS-XaaS Demo","se_identity":identity()})
        if path=="/api/state":
            local=_active_state(); authed=bool(_session_api_key or os.environ.get("INFOBLOX_API_KEY")); verified=bool(_readiness and (_readiness.get("reconciliation") or {}).get("verified"))
            rec=(_readiness or {}).get("reconciliation") or {"state":"unverified","verified":False,"detail":"Credential/readiness required"}
            visible=local if authed and verified and rec.get("state") in {"verified","partial"} else None
            return self._json({"se_identity":identity(),"shared_identity":identity()=="ssm-user","deployment":visible,"local_record_detected":bool(local),"local_record_phase":(local or {}).get("phase") if authed else None,"reconciliation":rec,"job":_job_dict(_current),"readiness":_readiness,"credentials":{"infoblox_api_key_configured":authed}})
        if path=="/" or path=="/index.html": f=STATIC/"index.html"
        elif path=="/app.js": f=STATIC/"app.js"
        elif path=="/style.css": f=STATIC/"style.css"
        else: self.send_error(404); return
        b=f.read_bytes(); c="text/html" if f.suffix==".html" else "text/javascript" if f.suffix==".js" else "text/css"
        self.send_response(200); self.send_header("Content-Type",c); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        path=urlparse(self.path).path
        try:
            if path=="/api/job/stop": return self._json({"stopped":stop_job()})
            if path=="/api/credentials":
                global _session_api_key
                body=self._body(); key=str(body.get("infoblox_api_key") or "").strip()
                if not key: return self._json({"error":"Infoblox API key is required"},400)
                _session_api_key=key
                return self._json({"configured":True,"persisted":False})
            if path=="/api/readiness": return self._json(run_readiness())
            if path.startswith("/api/run/"):
                action=path.rsplit("/",1)[1]; body=self._body(); args=[]
                allowed={"setup","readiness","deploy","status","traffic","cleanup"}
                if action not in allowed: return self._json({"error":"unsupported action"},400)
                if action=="readiness": return self._json(run_readiness(),200)
                if action=="deploy":
                    # Backend-authoritative gate: never trust a previous browser readiness result.
                    gate=run_readiness()
                    if not gate.get("deployment_ready"):
                        blockers=[c for c in gate.get("checks",[]) if c.get("scope")=="deployment" and c.get("ok") is not True]
                        return self._json({"error":"Deployment blocked by backend prerequisite check","blockers":blockers},412)
                    rec=gate.get("reconciliation") or {}
                    if body.get("new") and rec.get("state") in {"verified","partial"}:
                        return self._json({"error":"Existing deployment record requires resume/review; new deployment blocked","reconciliation":rec},409)
                    if (not body.get("new")) and _active_state() and rec.get("state") != "verified":
                        return self._json({"error":"Resume blocked until existing deployment ownership/state is fully verified","reconciliation":rec},409)
                    if body.get("new"): args.append("--new")
                    if body.get("dry_run"): args.append("--dry-run")
                if action=="cleanup":
                    st=_active_state(); expected=(st or {}).get("deployment_id")
                    if not expected or body.get("confirm_deployment_id") != expected: return self._json({"error":"cleanup confirmation must exactly match active deployment ID"},400)
                    args += ["--deployment-id", expected]
                return self._json(start_job(action,args),202)
            self.send_error(404)
        except RuntimeError as e: self._json({"error":str(e)},409)
        except Exception as e: self._json({"error":str(e)},500)
    def log_message(self,fmt,*args): pass

def serve(host="127.0.0.1",port=8787,pidfile=None):
    if host not in {"127.0.0.1","localhost","::1"} and os.environ.get("INFOBLOX_DEMO_ALLOW_REMOTE_WEB") != "1":
        raise RuntimeError("Refusing non-local web bind. Use SSM port forwarding. Set INFOBLOX_DEMO_ALLOW_REMOTE_WEB=1 only after adding external authentication/TLS.")
    secure_workspace(create=True)
    print("Infoblox NIOS-XaaS Demo")
    print("-" * 44)
    print(f"Web UI:      http://{host}:{port}")
    print(f"SE Identity: {identity()}" + (" (TEST/SHARED IDENTITY)" if identity() == "ssm-user" else ""))
    print("Access:      Localhost via authenticated SSM port forwarding")
    if identity() == "ssm-user":
        print("WARNING: generic ssm-user is suitable only for single-user testing.")
        print("         Production multi-SE mode requires SSO / SSM Run As.")
    try:
        server=ThreadingHTTPServer((host,port),H)
    except OSError as e:
        if getattr(e, "errno", None)==98:
            raise RuntimeError(f"Web UI port {port} is already in use. Run: demo web status") from e
        raise
    def _shutdown(signum,frame):
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,_shutdown); signal.signal(signal.SIGINT,_shutdown)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if pidfile:
            try:
                if Path(pidfile).exists() and Path(pidfile).read_text().strip()==str(os.getpid()): Path(pidfile).unlink()
            except Exception: pass
    return 0
