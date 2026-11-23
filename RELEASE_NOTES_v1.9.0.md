# v1.9.0

- Backend-authoritative prerequisite and entitlement checks before every deploy/resume mutation.
- Required Infoblox capabilities are probed and classified rather than inferred from configuration.
- Product naming standardized as **Infoblox NIOS-XaaS Demo**.
- Standard SE startup/UI hides the raw workspace path and shows effective SE identity.
- Generic `ssm-user` is clearly marked test/shared; production mode requires SSO / SSM Run As.
- v1.8 GUI-first reconciliation, cleanup persistence, secret cleanup, ownership protection and web lifecycle management retained.
