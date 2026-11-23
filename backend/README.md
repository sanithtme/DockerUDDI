# Backend

Python backend for the Infoblox NIOS-XaaS Demo platform.

- `deployment/` - AWS + Infoblox infrastructure deployment/reconciliation engine.
- `src/` - packaged CLI, telemetry, DNS/DHCP/TD traffic, safety, orchestration, and local web service.
- `unified_demo.py` - compatibility orchestration entrypoint used by the launcher.

Install from the repository root with `pip install -e .`; `pyproject.toml` maps package discovery to `backend/src`.
