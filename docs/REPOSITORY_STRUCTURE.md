# Repository Structure

```text
infoblox-unified-sales-demo/
├── backend/
│   ├── deployment/          # AWS + Infoblox deploy/reconcile/cleanup engine
│   ├── src/                 # installable Python packages, CLI, telemetry, web backend
│   └── unified_demo.py      # unified orchestration
├── frontend/
│   ├── static/              # browser UI source (HTML/CSS/JS)
│   └── README.md
├── config/                  # safe configuration examples
├── docs/                    # architecture, SE deployment, web UI, safety, workflows
├── scripts/                 # bootstrap, helpers, frontend sync
├── tests/                   # automated tests and fake APIs
├── integration/             # integration contract/prompt/examples
├── data/                    # example data only
├── pyproject.toml           # package + demo CLI entry point
└── README.md                # primary operator/admin entry point
```

The admin owns the Git checkout. SE runtime state is never stored in this repository; it lives under the configured per-user workspace (normally `~/.infoblox-demo`).

`frontend/static/` is the editable UI source. `scripts/sync_frontend.sh` copies it into `backend/src/demo_web/static/` for Python packaging. The web backend remains a thin adapter over the same `demo` CLI/deployment engine.
