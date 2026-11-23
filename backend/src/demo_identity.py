from __future__ import annotations
import getpass, os, stat
from pathlib import Path

def identity():
    return getpass.getuser()

def production_mode():
    return os.environ.get('INFOBLOX_DEMO_PRODUCTION','0') == '1'

def workspace():
    return Path(os.environ.get('INFOBLOX_DEMO_WORKSPACE', str(Path.home()/'.infoblox-demo'))).expanduser().resolve()

def secure_workspace(create=False):
    w=workspace(); user=identity()
    if create:
        w.mkdir(parents=True, exist_ok=True); os.chmod(w,0o700)
    if production_mode() and user == 'ssm-user':
        raise RuntimeError('Production multi-SE mode requires SSM Run As / a unique Linux user; generic ssm-user is not allowed.')
    if w.exists():
        st=w.stat()
        if st.st_uid != os.geteuid():
            raise RuntimeError(f'Workspace security check failed: {w} is not owned by current user {user}.')
        os.chmod(w,0o700)
    return w

def secure_file(path: Path):
    if path.exists(): os.chmod(path,0o600)
