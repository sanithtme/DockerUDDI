# Frontend

Browser UI source for the Infoblox NIOS-XaaS Demo controller.

The production Python package serves the packaged copy under `backend/src/demo_web/static/` so `demo web` remains a single command. After editing files in `frontend/static/`, run:

```bash
./scripts/sync_frontend.sh
```

The service binds to `127.0.0.1:8787` by default and is intended to be reached through AWS SSM port forwarding. Do not expose it directly through the EC2 security group.
