# v1.5.0

- Added session-only Infoblox API-key entry in localhost web UI; key is held in backend memory and is not persisted.
- Added structured Readiness results for deployment and traffic prerequisites.
- Deployment actions are gated by readiness and saved deployment state.
- Corrected lifecycle rendering so only confirmed backend checkpoints receive completion marks.
- Added RESUMABLE / DEPLOYING / DEMO READY deployment status semantics.
- Added Infoblox-oriented light/teal UI styling.
- Added explicit prerequisite guidance for missing configuration, credentials, AWS/control-plane access, DNS/DHCP settings, Asset Insights, and TIDE.
