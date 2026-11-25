# Backend MVP v1.1.0

Permission/bootstrap hardening release.

- `install-demo.sh` is executable and performs one-time `/var/lib/infoblox-nios-xaas-demo-mvp` bootstrap with narrowly scoped sudo.
- Docker daemon access is checked before runtime creation.
- Runtime workspaces use mode 0700; no chmod 777 workaround is used.
- Container preflight verifies `/workspace` write access, CLI imports, `demo setup`, and status behavior before READY.
- Failed preflight containers are removed automatically and recent logs are printed.
- Bind-mount chmod EPERM/EACCES is tolerated only when the workspace is already writable/usable.
- Image version bumped to backend-mvp:1.1.0.
