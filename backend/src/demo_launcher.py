"""Single front door for a shared, admin-installed multi-user sales demo."""
from __future__ import annotations
import argparse, getpass, os, shutil, signal, subprocess, sys, time, urllib.request
from pathlib import Path
from demo_identity import identity, secure_workspace, secure_file

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = Path(os.environ.get("INFOBLOX_DEMO_WORKSPACE", str(Path.home() / ".infoblox-demo"))).expanduser().resolve()
DEPLOY_COMMANDS = {"readiness", "doctor", "deploy", "status", "cleanup", "configure-telemetry", "traffic", "telemetry"}
WEB_PID = WORKSPACE / "web-server.pid"
WEB_LOG = WORKSPACE / "logs" / "web-server.log"

def _init_workspace() -> int:
    secure_workspace(create=True)
    for d in ("deployment", "state", "reports", "logs"):
        (WORKSPACE / d).mkdir(exist_ok=True); os.chmod(WORKSPACE / d, 0o700)
    cfg = WORKSPACE / "config.yaml"
    if not cfg.exists():
        shutil.copy2(ROOT / "config" / "unified.example.yaml", cfg); created = True
    else: created = False
    secure_file(cfg)
    user=identity(); print(f"Sales user: {user}")
    if user == 'ssm-user':
        print('WARNING: Session Manager is using shared OS user ssm-user.')
        print('         Fine for single-user testing; NOT for concurrent sales users.')
        print('         Configure SSM Run As / unique Linux users before multi-user rollout.')
    print(f"Workspace: {WORKSPACE}")
    print(f"Config: {cfg}" + (" (created from template)" if created else " (preserved)"))
    print("Next: start the UI with: demo web start")
    return 0

def _pid():
    try: return int(WEB_PID.read_text().strip())
    except Exception: return None

def _alive(pid):
    if not pid: return False
    try: os.kill(pid, 0); return True
    except OSError: return False

def _health(host, port, timeout=1.5):
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/health", timeout=timeout) as r:
            return r.status == 200
    except Exception: return False

def _web_status(host, port, quiet=False):
    pid=_pid(); alive=_alive(pid); healthy=_health(host,port) if alive else False
    if pid and not alive:
        WEB_PID.unlink(missing_ok=True); pid=None
    state='RUNNING' if healthy else ('UNHEALTHY' if alive else 'STOPPED')
    if not quiet:
        print(f"Web UI: {state}")
        print(f"Address: http://{host}:{port}")
        print(f"PID: {pid or '-'}")
        print(f"Workspace: {WORKSPACE}")
        print(f"Log: {WEB_LOG}")
    return state,pid

def _web_start(host,port):
    secure_workspace(create=True); (WORKSPACE/'logs').mkdir(exist_ok=True); os.chmod(WORKSPACE/'logs',0o700)
    state,pid=_web_status(host,port,quiet=True)
    if state=='RUNNING':
        print(f"Web UI already running (PID {pid}) at http://{host}:{port}"); return 0
    if state=='UNHEALTHY':
        print(f"ERROR: Existing web process PID {pid} is unhealthy. Run: demo web restart",file=sys.stderr); return 2
    WEB_LOG.parent.mkdir(parents=True,exist_ok=True)
    log=WEB_LOG.open('ab', buffering=0)
    env=os.environ.copy(); env['INFOBLOX_DEMO_WORKSPACE']=str(WORKSPACE); env['INFOBLOX_DEMO_OWNER']=identity()
    p=subprocess.Popen([sys.executable,'-c','import sys; from demo_launcher import main; sys.exit(main())','web','_serve','--host',host,'--port',str(port)],cwd=str(ROOT),env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
    WEB_PID.write_text(str(p.pid)); os.chmod(WEB_PID,0o600)
    for _ in range(30):
        if _health(host,port,.5):
            print(f"Web UI started (PID {p.pid}) at http://{host}:{port}")
            print(f"Log: {WEB_LOG}"); return 0
        if p.poll() is not None: break
        time.sleep(.2)
    print(f"ERROR: Web UI failed to become healthy. Check: {WEB_LOG}",file=sys.stderr); return 2

def _web_stop(host,port):
    state,pid=_web_status(host,port,quiet=True)
    if state=='STOPPED': print('Web UI already stopped.'); return 0
    try: os.kill(pid,signal.SIGTERM)
    except ProcessLookupError: pass
    for _ in range(30):
        if not _alive(pid): break
        time.sleep(.2)
    if _alive(pid):
        print(f"Web process {pid} did not stop gracefully; terminating it.")
        os.kill(pid,signal.SIGKILL)
    WEB_PID.unlink(missing_ok=True)
    for _ in range(15):
        if not _health(host,port,.2): break
        time.sleep(.2)
    print('Web UI stopped.'); return 0

def _web_cli(args):
    wp=argparse.ArgumentParser(prog='demo web')
    wp.add_argument('action',nargs='?',default='foreground',choices=['foreground','start','status','stop','restart','_serve'])
    wp.add_argument('--host',default='127.0.0.1'); wp.add_argument('--port',type=int,default=8787)
    wa=wp.parse_args(args)
    if wa.action=='status': _web_status(wa.host,wa.port); return 0
    if wa.action=='start': return _web_start(wa.host,wa.port)
    if wa.action=='stop': return _web_stop(wa.host,wa.port)
    if wa.action=='restart':
        _web_stop(wa.host,wa.port); return _web_start(wa.host,wa.port)
    from demo_web.app import serve
    return serve(wa.host,wa.port, pidfile=WEB_PID if wa.action=='_serve' else None)

def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] in {"setup", "init"}: return _init_workspace()
    if argv and argv[0] == "workspace": print(WORKSPACE); return 0
    if argv and argv[0] == "web": return _web_cli(argv[1:])
    if not argv or argv == ["--help"] or argv == ["-h"]:
        print(f"""usage: demo COMMAND [options]\n\nUnified Infoblox NIOS-XaaS sales demo\n\nUser workspace: {WORKSPACE}\n\nFirst use:\n  demo setup\n  demo workspace\n  demo web start\n  demo web status\n  demo web stop\n  demo web restart\n\nDeployment:\n  demo readiness\n  demo deploy --dry-run --new\n  demo deploy --new\n  demo deploy\n  demo status\n  demo cleanup\n\nTraffic:\n  demo traffic\n"""); return 0
    try: secure_workspace(create=False)
    except RuntimeError as e: print(f"ERROR: {e}", file=sys.stderr); return 2
    if not WORKSPACE.exists(): print("ERROR: User workspace does not exist. Run: demo setup", file=sys.stderr); return 2
    env = os.environ.copy(); env["INFOBLOX_DEMO_WORKSPACE"] = str(WORKSPACE); env["INFOBLOX_DEMO_OWNER"] = identity()
    cmd = None; skip = False
    for x in argv:
        if skip: skip = False; continue
        if x in {"-c", "--config", "--log-level"}: skip = True; continue
        if x.startswith("-"): continue
        cmd = x; break
    if cmd in DEPLOY_COMMANDS:
        forwarded = list(argv)
        if cmd == "readiness": forwarded[forwarded.index("readiness")] = "doctor"
        return subprocess.call([sys.executable, str(ROOT / "backend" / "unified_demo.py"), *forwarded], cwd=str(WORKSPACE), env=env)
    generated = WORKSPACE / "telemetry.config.yaml"; has_config = any(x in {"-c", "--config"} or x.startswith("--config=") for x in argv)
    if generated.exists() and not has_config: argv = ["--config", str(generated), *argv]
    elif not has_config and (WORKSPACE / "config.yaml").exists(): argv = ["--config", str(WORKSPACE / "config.yaml"), *argv]
    os.chdir(WORKSPACE); from demo_cli.main import main as telemetry_main; return telemetry_main(argv)
