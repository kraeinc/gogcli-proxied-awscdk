# gogcli-proxy Infra (CDK)

This Python AWS CDK app deploys the Google API proxy into the account and
region selected by the local environment binding:

- Two Python Lambdas: the Google API proxy and the owner-onboarding handler. The
  latter also dispatches DynamoDB stream events and runs delayed verification.
- One API Gateway REST API: managed Google routes require IAM SigV4 and a
  usage-plan API key; `/prd/onboarding/` uses its own owner session through the
  configured Authentik service.
- A retained DynamoDB metadata/operation table with a stream and TTL, plus an
  encrypted SQS verification queue and dead-letter queue. Closing the account page
  does not interrupt saved account operations.
- SSM SecureString storage for Google client secrets, refresh tokens, and owner
  OIDC credentials using the existing AWS-managed SSM key. DynamoDB and queue
  messages contain references and operation metadata, not Google secrets.
- Explicit bounded `gogcli-internal-*` application roles, caller policies,
  and CloudWatch alarms for worker errors, stream age, and dead-letter backlog.

The gogcli client is already wired to:

- send `X-GOG-Account: <email>`
- send signed `X-GOG-Google-Host: <original-google-host>` and preserve the original Google request path
- send `x-api-key: <api-key>`
- SigV4-sign the request for `execute-api`

Managed account API requests, including Gmail history reads during watch processing, use this proxy. `gog gmail watch pull` separately connects to Google Cloud Pub/Sub through its native subscriber client and Application Default Credentials. Those credentials authorize subscription reads and acknowledgements; they do not supply the managed Gmail account's OAuth token. See `internal/cmd/gmail_watch_pull.go` for the subscriber setup.

## Deploy

The source is this repository; the target is
`env/gogcli-prd/binding.json` (local and ignored). Product-owned access
and runtime permission boundaries are documented in [SECURITY.md](SECURITY.md).
Initial security setup uses the account bootstrap administrator; routine application
updates use `gogcli-live-deployment`. Inspection uses `gogcli-live-inspection`,
and CLI calls and operations use `gogcli-live-operation`.

```bash
aws --profile gogcli-live-deployment --region us-east-2 sts get-caller-identity
npx --yes aws-cdk@2.1148.1 deploy GogcliGoogleProxyApi \
  --app 'uv run --python 3.11 --with-requirements infra/requirements.txt python infra/app.py' \
  --context environment=gogcli-prd --profile gogcli-live-deployment \
  --require-approval never --outputs-file env/gogcli-prd/access.json
```

The first deployment supplies `ClientApiKeyValue` securely; routine updates reuse
that NoEcho CloudFormation parameter. Never put its value in tracked files.
The stack uses `CliCredentialsStackSynthesizer` and product-owned runtime roles.
The bootstrap asset infrastructure is defined by `infra/assets-template.json`.

The generated CDK outputs in `env/gogcli-prd/access.json` are grouped under
`GogcliGoogleProxyApi` and contain these non-secret access facts:

| Output | Use |
| --- | --- |
| `ProxyBaseUrl` | CLI proxy base URL, ending in `/prd/` |
| `ApiKeyId` | Identifier for the usage-plan key; not its secret value |
| `ProxyInvokeArns` | JSON array string of the six exact product invocation resources |
| `SetupUrl` | Published HTTPS owner account connections page, ending in `/prd/onboarding/` |
| `GoogleCallbackUrl` | Exact redirect URI for the Google Web application client |
| `OwnerCallbackUrl` | Exact Authentik redirect URI |
| `OnboardingTable` | Persisted account and operation metadata table |
| `OnboardingRoleArn` | Application role used by signed verification reads |

The invocation list contains these resource suffixes under this exact API and
`prd`: `*/gmail/*`, `*/drive/v3/*`, `*/upload/drive/v3/*`,
`*/resumable/upload/drive/v3/*`, `*/calendar/v3/*`, and `GET/proxy/v1/accounts`. Inventory is GET-only;
this grant does not include onboarding, other stages, or generic
Google HTTP batch routes. Account access and caller/account policy still apply
after API Gateway accepts a signed request.

The operation role's invocation grants and workload ceilings are owned by
`GogcliProductSecurity`. Refresh its exact-resource binding as part of any API or
state-resource replacement. The application no longer depends on JDev grants.

## Stable public address

The local binding fixes `public_domain_name` under its configured Route53 zone. The application owns a retained DNS-validated regional certificate,
API Gateway custom domain, and `/prd` mapping. The shared zone's validation CNAME
and alias are managed separately. All public URLs preserve the existing hostname.

`endpoint_enabled` supports the cross-account domain handoff; `workers_enabled`
controls background mappings. Both must be true for the completed production
migration. Domain and certificate deletion remains explicit because they are retained.

## Configure owner login and connect Google accounts

After deploying and generating `access.json`, configure this app on the existing
Authentik service from the repository root:

```bash
uv run --with requests --with boto3 python scripts/configure_owner_login.py
```

The script reads the concrete binding and CDK outputs, creates or updates the
app-specific confidential provider/application, and sets its owner group to
exactly the usernames in `binding.owners[]`. The
provider issues `sub_mode=user_uuid`, so the script writes each member's Authentik
UUID back into `binding.owners[].sub` — the value the runtime owner→caller map
(`ONBOARDING_OWNER_CALLERS`) and account ownership are keyed on. It reuses the
shared authorization/invalidation flows and signing key and registers
`OwnerCallbackUrl` exactly. Authentik API access comes from the installed
credential catalog; the client credentials are saved back to that catalog and SSM
SecureString without being printed. Its final read-only checks verify provider
discovery, JWKS, the exact callback, and owner membership. Run it before the CDK
deploy so each mapped owner's `sub` is present. Adding a person is a separate
operational step: create their Authentik user, add a `binding.owners[]` entry,
re-run this script, then redeploy.

## Configure the Google application

The local binding identifies the target environment and its Google application.
Use its downloaded **Web application** client JSON; keep the file outside the
repository.

Before provisioning, inspect the existing Google Console configuration and
confirm the selected service APIs are enabled, the scope list includes the
selected services, and the intended audience can approve consent. Confirm the
Web client's redirect URI is exactly `GoogleCallbackUrl` from local
`access.json`. The callback is permanent across API replacements; register no
generated API hostname. The callback domain and Google project owner are
separate configuration values. JSON and imported metadata
cannot establish API enablement, publishing status, test users, or Workspace approval. Record only settings actually observed.
For Gmail/Drive setup after confirming Testing status:

```bash
just configure-google-application /absolute/path/to/client.json gmail,drive testing
```

Use `gmail,drive,calendar` only after confirming Calendar API and its scope;
use `production` only after confirming that exact publishing state. The command
validates canonical project identity, Web-client type, callback, explicit AWS
identity and target; it stores an encrypted immutable client revision and
revision-bound API/publishing confirmations without printing secret values.
Reimporting the same client reuses its credential revision and creates no new
encrypted client secret; recording the operator review writes metadata. Replacement
revisions leave installed connections pinned to their original client until a
successful reconnect. The operator handles provisioning failures here; the
account page contains no credential upload or configuration controls.

Testing is supported. Google's seven-day refresh-token expiry applies to Testing
applications using these scopes unless an applicable documented exception is
established. Workspace trust concerns each organization's users; personal Gmail
and other organizations do not inherit it. Check the actual audience/test-user
and publishing configuration before describing token lifetime. See
[Google's app-state overview](https://developers.google.com/identity/protocols/oauth2/production-readiness/overview).

Open `SetupUrl` and follow the [account connection guide](../docs/account-onboarding.md).
Each account chooses Gmail, Drive, and optional Calendar for the same application.
A blocked organization may require administrator approval for the canonical
client and requested scopes. Provisioning does not connect any Google account.

The shared service registry requests `openid` and `email` for identity, plus
`gmail.modify`, `drive`, and `calendar` for the selected services. The provisioned owner
policy allows those services' normal GET/POST/PUT/PATCH/DELETE routes; independent
account policies and Google permissions narrow what actually succeeds. These
scopes do not promise permanent Gmail deletion, Gmail settings operations,
large-file transfers, or content/folder/label filtering.

A fresh candidate refresh and minimal selected-service reads must pass before
installation. Gmail checks profile and at most one message ID; Drive checks the
account email and at most one file ID. Empty collections pass. **Installation marks
the account connected immediately**; the end-to-end proxy check then runs in the
background and never blocks that result. For it, the worker waits one propagation
window (`ONBOARDING_PROPAGATION_SECONDS`, default 20s) — long enough for the proxy's
allowlist cache (`GOG_ALLOWLIST_CACHE_TTL_SECONDS`, default 15s) to expire — then
repeats those probes through the signed proxy as the **verifier role**. Keep the
propagation window strictly above the allowlist cache TTL. A failing background
check flips the account to `needs_attention`; it never un-connects a good install.
The result records the service, revision, principal, and time; it does not prove
the actual CLI caller's IAM/policy access. Run inventory and the same minimal reads
as that caller for acceptance. Each completed check emits a `connection_completed`
wide log event with the total and per-phase seconds for latency analysis.

Google connection, the latest attempt, and desired tool access
are separate facts. Each login (`binding.owners[]`, keyed by its Authentik `sub`)
owns the accounts it connects, and an account's tool access is granted only to
that login's own caller role — `binding.owners[].caller_role_arn`, assembled into
the `ONBOARDING_OWNER_CALLERS` (`{sub: role_arn}`) runtime map. One person's
caller therefore never reaches another person's accounts. A login with no
`caller_role_arn` is **UI-only**: it can connect and manage accounts, but its
accounts receive verifier access only — no data-plane caller — and its
**Pause/Resume tool access** action is unavailable (`409 caller_not_configured`).
Connect enables the owner's caller unless a saved pause must be preserved.
**Pause tool access** removes that login's explicit email grant while retaining
Google authorization and limited verifier access. Reconnect preserves the flag
and installed connection until a usable replacement passes validation. Durable
account state survives temporary operation cleanup; recovery uses account-level
controls.

**Primary account.** Each login may mark one of its own connected accounts as
primary (`PUT /onboarding/v1/accounts/{email}/primary`, surfaced as
`setup.primaryEmail`). It is a per-person label stored on a single `OWNER#<sub>`
record; it does not change proxy authorization or the CLI's `default_account`.

Disconnect removes the verifier grant, every configured owner caller's grant,
and installed credentials through a persisted operation. It does not mutate Google content or revoke the shared
Google application's consent. Removal remains applying for one propagation window
after the final authorization write. Starting requests fail within the allowlist
cache bound; an already authorized request may finish within its
existing 27-second budget. Failures remain retryable and never report a completed
removal before its writes and propagation window finish.

An account that is **not connected** — never connected, or already disconnected —
can be removed from the owner's list entirely with `DELETE /onboarding/v1/accounts/{email}`
(the **Remove from list** action). This deletes only the saved metadata (and clears
it as the owner's primary if set); it is refused for an account that still holds a
credential or has an active operation, and it never touches Google.

For the first CLI caller, fetch the usage-plan key using `ApiKeyId` from the
generated access record:

```bash
aws --profile gogcli-live-operation --region us-east-2 apigateway get-api-key \
  --api-key '<ApiKeyId>' --include-value --query value --output text
```

Configure `proxy_base_url` from `ProxyBaseUrl`, `proxy_api_key` from the returned
value, `aws_profile` as `gogcli-live-operation`, and a verified `default_account` in the
CLI's `config.json`. Run `bin/gog config path` to locate it. Google credentials
stay on the server; the account guide provides the
first read-only CLI checks. Signed `GET /proxy/v1/accounts` returns only metadata
for the caller's permitted installed accounts and never reads account credential
parameters or Google data.

## SSM Parameters

The Lambda reads SSM parameters under `GOG_SSM_PREFIX` (default: `/gogcli-proxy`).

Parameter names use base64url (no padding) encoding for safety.

### Allowlist (deny-by-default)

Name:

- `<prefix>/allow/<caller_id_enc>`

Value JSON:

```json
{
  "emails": ["user@example.com"],
  "domains": ["example.com"]
}
```

Notes:

- `caller_id` comes only from API Gateway's authenticated request identity. Cognito identity IDs take precedence; otherwise `userArn` (or an ARN-valued `caller`) identifies the IAM principal.
- Assumed-role sessions use a stable role identity: `arn:aws:sts::123456789012:assumed-role/proxy-agent/session-name` becomes `arn:aws:iam::123456789012:role/proxy-agent`. Account, partition, and role remain part of the key; session names cannot grant another role's access. IAM user ARNs remain unchanged.
- Missing or invalid identities, including a bare `AROA...:session-name` without an ARN, are denied before reading allowlists. There is no `unknown` or session-name fallback.
- Each mapped owner caller and the verifier role has its own `allow/<caller_id_enc>` parameter; a promoted account is written only into its own owner's caller allowlist (plus the verifier's).
- Email/domain matching is case-insensitive. Operator-managed caller documents can use domains or `"*"`; managed owner/verifier access toggles require explicit-email-only grants.
- If a managed allowlist contains a wildcard/domain grant, account toggles fail with `409 broad_allowlist_requires_operator` instead of silently removing that configuration or claiming one email is revoked.

### Runtime identity and account metadata

Use the stable authenticated role ARN as the caller key. Session-name keys are
obsolete and are never consulted. Independent consumers need distinct IAM
principals when their permissions differ; a shared Developer role cannot express
per-session grants.

DynamoDB retains `CLIENT#<project-id>`, `SETUP`, and `ACCOUNT#<email>` facts.
`OP#` and scoped idempotency records retain terminal diagnostics for seven days.
Nonterminal work has explicit recovery/expiry handling rather than disappearing
through TTL. Queue messages contain operation IDs. Temporary secret references
stay internal and never enter public account/operation responses.

### Google Credentials (per account)

Name:

- `<prefix>/google/accounts/<email_enc>`

Value JSON: one of:

Service account (domain-wide delegation):

```json
{
  "type": "service_account",
  "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "service_account": {
    "type": "service_account",
    "project_id": "my-project",
    "private_key_id": "....",
    "private_key": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n",
    "client_email": "svc@my-project.iam.gserviceaccount.com",
    "client_id": "....",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}
```

OAuth refresh token:

```json
{
  "type": "oauth_refresh",
  "client_id": "....apps.googleusercontent.com",
  "client_secret": "....",
  "refresh_token": "....",
  "token_uri": "https://oauth2.googleapis.com/token"
}
```

Notes:

- For `service_account`, the proxy impersonates the requested `X-GOG-Account` email (domain-wide delegation subject).
- For `oauth_refresh`, omit `scopes` unless you know the refresh token was minted with those scopes.
- Warm Lambda invocations reuse access tokens separately for each account until 60 seconds before their reported expiry. Tokens without a usable expiry are never cached.
- SSM account and allowlist configuration caches cannot exceed 60 seconds. A changed credential configuration or default scope list invalidates that account's cached token when the new configuration is observed.

## Policy Enforcement (Lambda)

Policy is enforced in the proxy Lambda (deny-by-default) when `GOG_POLICY_ENABLED=true` (default).

Policy SSM prefix defaults to:

- `<GOG_SSM_PREFIX>/policy` (for example `/gogcli-proxy/policy`)

Policy documents:

1. `<policy_prefix>/default`
2. `<policy_prefix>/caller/<caller_id_enc>`
3. `<policy_prefix>/account/<email_enc>`

A valid default document is required, even when a caller document exists;
missing default returns `{"error":"policy_not_found"}`. Malformed configured
documents fail closed. Provisioning creates an empty default-deny document.

### Policy JSON schema (v1)

```json
{
  "version": 1,
  "default_effect": "deny",
  "rules": [
    {
      "id": "gmail-read",
      "effect": "allow",
      "priority": 100,
      "match": {
        "methods": ["GET"],
        "accounts": ["user@example.invalid"],
        "hosts": ["gmail.googleapis.com"],
        "path_regex": "^/gmail/v1/users/me/(labels|messages|threads)(/.*)?$",
        "query": {
          "forbid_keys": ["uploadtype"]
        }
      },
      "constraints": {
        "max_request_bytes": 1048576,
        "require_account_domain": ["example.invalid"]
      },
      "on_match": {
        "emit_event": true,
        "event_type": "proxy.policy.allow.gmail_read",
        "detail": {
          "policyVersion": "v1"
        }
      }
    },
    {
      "id": "deny-mutations",
      "effect": "deny",
      "priority": 90,
      "match": {
        "methods": ["POST", "PUT", "PATCH", "DELETE"]
      }
    }
  ]
}
```

Notes:

- Any matching explicit deny in default, caller, or account documents vetoes the request, regardless of priority.
- The caller document supplies positive permission when present; otherwise the default supplies it. A restrictive caller document cannot inherit unrelated default allows.
- An account document is an independent ceiling: it must also allow the request. A missing account document adds no ceiling.
- Within each document, `default_effect` applies when no rule matches. Priority and declaration order choose among equivalent matches, never allow over deny.
- Optional `match.accounts` contains exact normalized email addresses. An absent or empty list is unconstrained; use explicit addresses for account-dependent permission.
- Unknown keys fail closed. Policies authorize API operations, not response fields, Gmail label membership, or Drive folder membership.

For an account whitelist, use `default_effect: deny` and explicit allowed paths,
methods, and hosts. For an account denylist, use `default_effect: allow` plus
explicit denied operations. Both remain ceilings: an account allow cannot
create permission denied or absent in the caller document.

This replaces the obsolete shared priority-sorted override semantics. Before
rollout, inspect actual nonsecret policies and account metadata; explicitly
convert any configuration relying on account allows overriding caller denies.

Policy caches cannot exceed 30 seconds. Allowlist/account configuration caches
cannot exceed 60 seconds; environment values may shorten these bounds but cannot
extend them. Authorization runs before reusing a cached Google token.

### Policy trigger events (optional)

Enable match-triggered events:

```bash
export GOG_POLICY_EVENTS_ENABLED=true
export GOG_POLICY_EVENT_BUS_ARN='arn:aws:events:...:event-bus/your-bus'
```

When enabled and a matching rule has `on_match.emit_event=true`, Lambda emits an EventBridge event with decision metadata.
Trigger failures are logged but do not change allow/deny results.

## Routing, payloads, and timeouts

`X-GOG-Google-Host` is required and validated against the supported Google API host allowlist, `docs.google.com`, or a valid subdomain of `googleusercontent.com` for Photos Picker media. The original path is preserved, including upload prefixes and API versions. Path-only host inference is obsolete and has been removed. Upgrade clients and the handler together; older clients without the signed host header receive HTTP 400. Proxy authentication/account/routing headers are removed before forwarding, and Google redirects are returned to the client for another signed request. Duplicate routing headers, method overrides, malformed/ambiguous paths, and contradictory query representations fail before token minting or Google forwarding. Policy evaluates the prepared destination and the same repeated query parameters that are sent.

The request body cap is 4 MiB. `GOG_MAX_REQUEST_BYTES` may lower it, but cannot raise it. This leaves room for ordinary API Gateway event/base64 overhead below Lambda's 6 MiB invocation limit. Gmail's upstream 35 MiB raw-message limit does not apply to this proxy; the proxy body cap includes MIME/base64/JSON content transmitted to Google.

Ordinary responses have both a streamed raw-body cap (`GOG_MAX_RESPONSE_BYTES`, default 5,500,000 bytes) and a hard 6 MiB cap on the serialized Lambda response, including headers, base64 expansion, JSON escaping, and the response envelope. Oversized responses return HTTP 502, and upstream response streams are always closed.

Full Drive media downloads and exports opt into `X-GOG-Response-Mode: signed-url`.
After the existing caller/account/operation authorization, successful full responses
are staged in Lambda temporary storage (256 MiB maximum) and uploaded to the
stack-owned private, AES256-encrypted, TLS-only S3 bucket. The header is removed
before Google forwarding. The proxy returns a bounded
`application/vnd.gog.download+json` envelope containing a five-minute presigned
GET URL, the original status and sanitized headers, and the staged byte count.
The Go transport consumes the envelope internally and streams the S3 response
using a fresh request with no proxy credentials. It rejects redirects, invalid
destinations, and incomplete transfers. Metadata, range responses, and upstream
errors retain their ordinary response contract. See
[the download contract](../docs/proxy-downloads.openapi.yaml).

The proxy role has Get/Put/Delete access only to `downloads/*`; clients need no S3
IAM grant. Bucket policy limits signed GET age to five minutes. Objects expire
through a one-day lifecycle, with asynchronous S3 cleanup. A signed link is a
temporary bearer capability and remains usable until expiration even after proxy
access is paused; neither link nor content is logged. Failed staging returns no
link and attempts object cleanup; lifecycle expiry also handles interrupted work.
There is no persisted operation to resume: retrying the read creates a new opaque
object without mutating Google data. Do not publish these links or make the bucket
public. Retaining the bucket preserves lifecycle cleanup across stack removal.

Token minting and forwarding share a request budget capped at 27 seconds, or two seconds less than the Lambda invocation's remaining time if shorter. Connect/read timeouts use each phase's remaining budget, token refresh retries are bounded by its refresh deadline, and streamed chunks are checked against the request deadline. Expired budgets return HTTP 504 before starting another phase.

Run the complete backend verification gate from the repository root with `uv`,
`just`, and Node installed (CI uses Node 26):

```bash
just backend-ci
```

The gate runs existing Python 3.11 runtime and operator tests, synthesized AWS
infrastructure contracts, and a real Linux x86_64 Lambda asset build. Dependencies
use uv-managed environments and the repository requirements files. AWS tests use
dummy credentials and disabled instance metadata; they do not access a deployed
environment. The asset check downloads Linux wheels through uv and verifies
binary compatibility and bundled UI assets. Individual suites remain available
as `just proxy-test`, `just operator-test`, and `just infra-test`.

Maps/Places and public YouTube API-key modes also retain upstream project credentials and do not consume managed-account Google OAuth tokens. These ancillary API-key requests go directly to their provider; account-authenticated Google API requests use the proxy.
