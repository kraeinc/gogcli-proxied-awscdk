# Product-owned access

`security_app.py` owns the deployment, inspection, and operation entry roles
(`<role_prefix>-deployment`, `-inspection`, `-operation`, assumed by principals
outside the account) and three workload permissions boundaries. It uses direct
deployment credentials through `CliCredentialsStackSynthesizer`; it does not
assume CDK deployment or CloudFormation execution roles. The application stack
owns its separate proxy, onboarding, and API Gateway logging execution roles and
their inline permissions; these carry the `-internal-` label
(`<role_prefix>-internal-proxy`, `-internal-onboarding`, `-internal-apigw-logs`)
because only AWS services inside the account assume them. The asset
bootstrap stack also owns the AWS-managed API Gateway service-linked role needed
for a regional custom domain.

The security stack is administered using the dedicated account's initial
`OrganizationAccountAccessRole`. Its exact trusted principal is supplied in the
binding. A role trust policy does not grant the
principal permission to assume it; publish the corresponding identity-side grants
and local profiles through the identity owner's configuration.

- Deployment can manage only the named application CloudFormation stack and its
  product resources. It can manage the three exact runtime roles, subject to
  their fixed boundaries, and pass each only to its intended AWS service. It
  cannot manage entry roles, update existing runtime trust policies, remove boundaries,
  change managed policies, or deploy the security stack. Application code updates
  inherently give deployment control over the application's data and credentials.
- Inspection reads infrastructure metadata, excluding Lambda code/environment,
  API keys, parameter values, table items, objects, and log payloads.
- Operation reads/writes product data and credentials, reads application logs,
  uses the six signed route families, and manages existing queue deliveries and
  event-source mappings. It cannot change IAM or deploy infrastructure. This role
  is also the CLI caller; no additional caller role is required.

## Binding and bootstrap

Use a separate security binding file with these required fields. Values must
identify the actual destination, not the legacy account:

| Field | Value |
| --- | --- |
| `account_id`, `region` | Dedicated account ID and `us-east-2` |
| `role_prefix` | Product prefix such as `gogcli`; no environment suffix — the account runs one product |
| `principal_arn` | One approved IAM user or role ARN |
| `application_stack_name` | `GogcliGoogleProxyApi` |
| `ssm_prefix`, `stage` | `/gogcli-proxy`, `prd` |
| `ssm_key_arn` | Destination account's SSM encryption key ARN |
| `asset_bucket_arn` | Existing destination CDK asset bucket ARN |
| `public_domain_name` | Existing permanent product hostname |

The shared parent DNS zone remains centrally managed. Certificate validation
and the public alias are managed there during cutover. The application owns its
certificate, custom domain, and mapping; it does not write the shared DNS zone.
`endpoint_enabled` controls domain creation during handoff, and `workers_enabled`
controls the three background event-source mappings. Both are enabled after migration.
The `deployed_artifact` binding pins the migrated ZIP and its S3 version; both
functions use the exact previously deployed bytes. The API key is a NoEcho
CloudFormation parameter. Routine updates reuse its existing value.

1. Bootstrap the dedicated account, asset bucket, SSM key, and DNS/certificate
   prerequisites using the account administrator. Deploy security without
   `application_resources`. The three entry roles and workload boundaries exist;
   the operation role has no data or invocation grants yet. Initial boundaries
   permit the application's generated resource-name namespaces and target-account
   API routes. API Gateway control-plane grants are account-local and regional;
   this is a dedicated product account.
2. Set the application binding's `role_prefix`, destination account/key/profile,
   an `owners[]` entry per operator login (`username`, `sub`, `caller_role_arn`;
   the first operator's caller is the operation role), and `permissions_boundary_arns`
   map (`proxy`, `onboarding`, `apigw-logs`) to the security outputs. The old
   singular boundary binding field and the singular `client_role_arn` have been
   removed.
3. Deploy the inactive destination application, using the product deployment role.
   Account for domain handoff and disabled workers separately in the migration.
4. Read the actual generated resources. Add `application_resources` containing
   exact `table_arn`, `download_bucket_arn`, `queue_arns`, `api_id`, `api_key_id`,
   and `event_source_mapping_arns`. Update security using the bootstrap
   administrator. This tightens the workload ceilings to discovered resources
   and enables operation access. Do this before application acceptance or cutover.
5. Verify real permitted and denied calls using each assumed entry role. Use the
   deployment role for later application changes; use the administrator only for
   reviewed security-stack changes. If an application replacement changes resource
   IDs, update the security binding and ceilings as part of that replacement.

From the repository root, synthesize using the existing local toolchain:

```sh
cdk synth GogcliProductSecurity --app 'uv run --python 3.11 --with-requirements infra/requirements.txt python infra/security_app.py' --context security_binding=/absolute/path/to/security-binding.json
```

For CDK CLI deployment, pass the same Python entrypoint/context with the explicit
destination administrator profile. Keep concrete bindings and generated security outputs local and ignored. Entry roles and boundaries are retained on stack deletion and
require explicit cleanup when retiring the product account.
