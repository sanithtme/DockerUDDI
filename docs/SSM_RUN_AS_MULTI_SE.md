# SSM Run As and Multi-SE Isolation

Production multi-user operation must not share the generic `ssm-user` identity.

## Target

Corporate SSO / AWS IAM Identity Center -> Session Manager -> SSM Run As -> unique Linux user -> `/home/<se>/.infoblox-demo`.

The application validates that the workspace is owned by the effective Linux user. Set `INFOBLOX_DEMO_PRODUCTION=1` to reject `ssm-user` entirely.

## Administrator prerequisites

1. Give approved SE identities permission to start Session Manager sessions only against the sales controller.
2. Configure Session Manager Run As according to the organization's IAM Identity Center/SSM policy so each SE receives a unique Linux identity.
3. Provision the corresponding Linux accounts on the controller. `scripts/create_se_user.sh <linux-user>` is provided for the OS-side step.
4. Keep the application checkout/admin virtualenv centrally managed and read-only to SEs.
5. Do not expose SSH or the web UI port publicly; use SSM and SSM port forwarding.

## Security permissions

Each workspace is mode `0700`; sensitive local files are mode `0600`. Deployment-owned AWS resources include `Owner`, `ManagedBy`, and `DeploymentId` tags where created by the engine.
