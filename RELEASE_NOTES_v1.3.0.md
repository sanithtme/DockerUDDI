# v1.3.0

- Added localhost-only web control plane (`demo web`).
- Added live job output/state polling and browser reconnect behavior.
- Added explicit new-deployment confirmation and deployment-ID cleanup confirmation.
- Added interrupt action; resume remains `demo deploy`.
- Refuses non-loopback web bind unless explicitly overridden.
- Added `docs/WEB_UI_GUIDE.md` and README web instructions.
- Preserves v1.2.0 deployment engine, ownership guards, per-user workspace model and CLI.

Validation: Python compilation passed; loopback health/page smoke test passed; existing pytest suite showed no failure before the execution-time limit interrupted the longer run.
