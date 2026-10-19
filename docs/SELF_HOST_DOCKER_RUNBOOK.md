# Self-Hosted Docker Runbook

This runbook covers institutional self-host deployment for CredTrail using Docker, Postgres, and
S3-compatible object storage.

## Runtime Profile

- API runtime: Node (`apps/api-worker/src/node-server.ts`)
- Queue worker: Node polling process (`apps/api-worker/src/node-worker.ts`)
- Database: Postgres 14+
- Object storage: an existing AWS S3 or Cloudflare R2 bucket
- Production installs must run with `APP_ENV=production`. The Docker image defaults to
  production, and the reference compose stack sets `APP_ENV=production`.

## Required Environment Variables

- `DATABASE_URL`
- `S3_BUCKET`
- `S3_REGION` (the AWS bucket region, or `auto` for R2)
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `PLATFORM_DOMAIN`
- `PUBLIC_APP_ORIGIN` (the public app origin, including `https://` and any non-default port)
- `APP_ENV`
- `BETTER_AUTH_SECRET` (stable, high-entropy secret; rotate only with a session reset plan)
- `BETTER_AUTH_TRUSTED_ORIGINS` (comma-separated public origins allowed to use hosted auth)
- `PORT`

Optional:

- `S3_ENDPOINT` (required for R2; leave empty for AWS S3)
- `S3_FORCE_PATH_STYLE` (defaults to `false`)
- `TRUSTED_PROXY_CIDRS` (comma-separated IPv4/IPv6 addresses or CIDRs; empty by default)
- `JOB_PROCESSOR_TOKEN`
- `AWS_SESSION_TOKEN`
- `EMAIL_PROVIDER` (`smtp`, `ses`, or `none`; defaults to `none`)
- `AWS_SES_REGION` (defaults to `S3_REGION` if omitted)
- `TRANSACTIONAL_EMAIL_FROM_ADDRESS` (required for SMTP or SES)
- `AWS_SES_CONFIGURATION_SET`
- `TRANSACTIONAL_EMAIL_FROM_NAME` (defaults to `CredTrail`)
- `TRANSACTIONAL_EMAIL_REPLY_TO` (optional reply mailbox)
- `ISSUANCE_EMAIL_BCC` (optional comma-separated badge notification copies; see below)
- SMTP connection and secret settings (see **Configure SMTP**)

Worker notes:

- The worker process runs the same queue-processing route logic in-process.
- Configure worker containers with the same DB/storage credentials and production auth secret as
  the API container. Runtime identity is assigned by the Node factory, not an environment override.
- Production Node API and worker use pooled `DATABASE_URL` connections. The Cloudflare Worker
  runtime continues to require Hyperdrive in production. Missing Node `DATABASE_URL` fails startup.

## Configure Docker Compose

The default Compose stack runs database migrations and starts the API and queue worker. It connects
to the Postgres database you specify in `DATABASE_URL`, such as AWS RDS or another managed service.
An optional Compose file adds local Postgres. Credentials and artwork are stored in your S3 or R2
bucket. Create a private bucket before starting the stack; Compose does not create or manage it.

From the app repository, copy the settings template:

```bash
cp .env.selfhost.example .env.selfhost
```

Edit `.env.selfhost` on your machine. This file is gitignored and excluded from Docker builds.
Enter your database URL, bucket settings, and credentials there; keep them out of commits, issue
reports, and chat messages.

### Connect to managed Postgres

Set `DATABASE_URL` to your provider's connection URL. Use the same database for migrations, the API,
and the worker; Compose passes this value to all three. The database must exist, and the database
user must have permission to apply the schema migrations. URL-encode special characters in the
username and password.

Use certificate-verified TLS for managed databases. A provider with a publicly trusted certificate
can use a URL ending in `?sslmode=verify-full`.

For AWS RDS, create a `.local` directory and download the appropriate
[RDS CA certificate bundle](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html)
to `.local/rds-ca.pem`. Use the RDS endpoint hostname in the URL so certificate verification can
check its identity. Add these query parameters to your URL:

```text
?sslmode=verify-full&sslrootcert=/run/credtrail/database-ca.pem
```

The certificate path refers to a file inside each container. Create `.local/compose.database-tls.yml`
with this content to mount the downloaded certificate read-only:

```yaml
x-database-tls: &database_tls
  volumes:
    - type: bind
      source: ./.local/rds-ca.pem
      target: /run/credtrail/database-ca.pem
      read_only: true
      bind:
        create_host_path: false

services:
  migrate:
    <<: *database_tls
  app:
    <<: *database_tls
  worker:
    <<: *database_tls
```

Allow the Docker host to reach the database through your network and database security rules.
For RDS, run the host in a network that can reach the instance and allow its connections in the RDS
security group. See [RDS PostgreSQL TLS connections](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html).

### Configure object storage

For AWS S3, use the bucket's region and leave `S3_ENDPOINT` empty:

```dotenv
S3_BUCKET=your-credtrail-bucket
S3_REGION=us-east-1
S3_ENDPOINT=
S3_FORCE_PATH_STYLE=false
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
```

Give the AWS identity access to check the bucket and read, write, and delete objects:
`s3:ListBucket` on the bucket, and `s3:GetObject`, `s3:PutObject`, and `s3:DeleteObject` on its objects.
Keep the bucket private; CredTrail serves public credential and artwork URLs through the app.

For Cloudflare R2, use `auto` as the region and the S3 API endpoint from your bucket's dashboard:

```dotenv
S3_BUCKET=your-credtrail-bucket
S3_REGION=auto
S3_ENDPOINT=https://<ACCOUNT_ID>.r2.cloudflarestorage.com
S3_FORCE_PATH_STYLE=false
AWS_ACCESS_KEY_ID=your-r2-access-key-id
AWS_SECRET_ACCESS_KEY=your-r2-secret-access-key
```

Create an R2 API token with **Object Read & Write** access restricted to this bucket. Use its S3
Access Key ID and Secret Access Key. See [R2 authentication](https://developers.cloudflare.com/r2/api/tokens/)
and the [R2 SDK configuration](https://developers.cloudflare.com/r2/examples/aws/aws-sdk-js-v3/).

### Start with managed Postgres

Start the default stack with your local settings:

```bash
docker compose --env-file .env.selfhost -f docker-compose.selfhost.yml up --build --wait
```

If you created the RDS certificate mount file, include it in the command:

```bash
docker compose --env-file .env.selfhost -f docker-compose.selfhost.yml \
  -f .local/compose.database-tls.yml up --build --wait
```

Migrations must finish successfully before the API and worker start. The API becomes healthy when
the database and bucket are reachable. Missing database or bucket settings stop Compose with a
message naming the value to supply.

No `JOB_PROCESSOR_TOKEN` is needed for this stack. The API and queue worker use the packaged
Node bundles, and the worker processes jobs directly against Postgres.

To stop the default stack, run the same Compose command with `down` instead of `up --build --wait`.
Compose does not delete your managed database or external bucket, including when you use
`down --volumes`. Use your providers' database and bucket backup procedures.

### Optional: start with local Postgres

For local validation, set this URL in `.env.selfhost`:

```dotenv
DATABASE_URL=postgres://credtrail:credtrail@postgres:5432/credtrail
```

Include the local database file when starting the stack:

```bash
docker compose --env-file .env.selfhost -f docker-compose.selfhost.yml \
  -f docker-compose.selfhost-postgres.yml up --build --wait
```

This file adds Postgres with a health check and makes migrations wait for it. Postgres runs on the
internal Compose network; it does not publish a database port on your host. The API and worker use
the same `DATABASE_URL` as migrations.

Postgres records use the named volume `postgres-data`. Docker Compose prefixes its name with the
project name. Keep the same project name and include the local database file when restarting or
upgrading so the stack reuses its data. To stop this stack and preserve the database, run:

```bash
docker compose --env-file .env.selfhost -f docker-compose.selfhost.yml \
  -f docker-compose.selfhost-postgres.yml down
```

The next `up` reuses the database volume. For this local setup, `down --volumes` deletes the local
database; it does not delete objects from your external bucket. Keep regular database and bucket
backups.

### Configure production identity and email

The Compose stack leaves outbound email disabled. Configure email delivery before offering
production email sign-in or invitations.

Do not use `APP_ENV=development` for real self-host installs. Development mode enables local
debugging behavior such as single-use database connections and development auth shortcuts.

Before using the compose stack beyond local validation, replace the sample `BETTER_AUTH_SECRET`
with a stable random value and set `BETTER_AUTH_TRUSTED_ORIGINS` to the public HTTPS origin for
the deployment.

Choose `EMAIL_PROVIDER=smtp` to use your mail service, or `EMAIL_PROVIDER=ses` to use the Amazon
Simple Email Service (SES) API. Email stays disabled when the provider is omitted or set to `none`.
Both providers support an optional `TRANSACTIONAL_EMAIL_REPLY_TO` mailbox.

#### Configure SMTP

CredTrail sends directly to your mail service through Nodemailer. Configure these settings in
`.env.selfhost`; Compose passes them to both the API and worker:

```dotenv
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.example.edu
SMTP_SECURITY=starttls
SMTP_USERNAME=your-smtp-username
SMTP_PASSWORD_FILE=/run/secrets/smtp_password
TRANSACTIONAL_EMAIL_FROM_ADDRESS=badges@example.edu
TRANSACTIONAL_EMAIL_FROM_NAME=Example University
TRANSACTIONAL_EMAIL_REPLY_TO=support@example.edu
```

Use SMTP credentials from your mail service. These credentials are independent of your S3 or R2
credentials. Some services issue SMTP credentials separately from their API credentials. Authorize
the sender address with your mail service, and configure its SPF, DKIM, and DMARC DNS records.

`SMTP_SECURITY=starttls` requires an encrypted upgrade and defaults to port 587. For immediate
TLS, use `SMTP_SECURITY=tls`, which defaults to port 465. Set `SMTP_PORT` only if your relay uses
another port. Use a DNS hostname in `SMTP_HOST`. CredTrail requires a valid certificate matching
that hostname and TLS 1.2 or newer. Plaintext SMTP and disabled certificate checks are unsupported.

Save your password in `.local/smtp-password`, and restrict access to that file. CredTrail preserves
password whitespace and removes only one final newline from a mounted password file. The file
must contain a nonempty password and be at most 64 KiB. Create `.local/compose.email.yml`:

```yaml
services:
  app:
    secrets:
      - smtp_password
  worker:
    secrets:
      - smtp_password

secrets:
  smtp_password:
    file: ./.local/smtp-password
```

For this setup, add `-f .local/compose.email.yml` to your Compose commands. Set exactly one of
`SMTP_PASSWORD_FILE` or `SMTP_PASSWORD`. Prefer a mounted file. If you put a password in
`.env.selfhost`, use single quotes to preserve literal dollar signs and spaces. Keep passwords
out of commands, commits, logs, and support reports.

For a relay that authorizes clients through network access, set `SMTP_AUTH=none` and leave
`SMTP_USERNAME`, `SMTP_PASSWORD`, and `SMTP_PASSWORD_FILE` empty. TLS is still required.
For a private certificate authority, mount its PEM certificate read-only in both containers
and set `SMTP_TLS_CA_FILE` to the container path. This file also has a 64 KiB limit.

Optional: set `ISSUANCE_EMAIL_BCC` to up to ten comma-separated mailboxes. These mailboxes receive
badge issuance notifications for **every tenant in this deployment**. Enable copies only when
those recipients are authorized to receive all of that learner information. Copies are disabled
by default. Sign-in links, password resets, invitations, governance messages, and operator test
messages never receive automatic BCC. Recipient-facing email headers do not reveal BCC addresses.

Transactional notifications include HTML and a plain-text alternative. Sign-in links, password
resets, member invitations, badge issuance, rule approvals, and lifecycle reminders share one
built-in CredTrail design. Institution-scoped messages use the institution name automatically;
unscoped sign-in messages use CredTrail. No template settings or additional dependencies are
required. The layout uses text and inline styles, so its content remains available when images
are blocked. This design is the same for SMTP, SES, and the Cloudflare email binding.

#### Track notification attempts

Application notifications create an `email_attempts` database record before contacting the mail
provider. If that record cannot be saved, CredTrail does not send the message. Records identify
the institution, message kind, recipient, related record, timestamps, and provider message ID;
they do not contain message bodies, sign-in links, or password-reset tokens.

- `accepted`: the provider accepted the message. This does not confirm inbox delivery.
- `failed`: rendering failed or the provider explicitly rejected the send.
- `skipped`: email is not configured, or development mode intentionally suppressed a sign-in email.
- `pending`: no conclusive result is recorded. The process may still be sending, may have stopped,
  or may have lost the provider's reply. Check the provider's records before resending.

A failed result write leaves the original attempt pending and emits `email_attempt_tracking_failed`.
Approval-job and lifecycle-reminder retries skip recipients whose logical notification is already
accepted or pending, so recovery from partial failures does not resend those messages. A reminder
is marked complete only after every intended recipient has provider acceptance. Badge issuance
receipts also retain a pending notification event before sending; email failure does not undo or
reissue the credential. Bounces and final mailbox delivery are not tracked by this workflow.

#### Pace notification batches

Approval and lifecycle-reminder batches allow at most two messages in flight, with at least
500 ms between send starts. An explicit SMTP temporary rejection or SES throttling response
pauses the remaining batch for 2 seconds. Repeated temporary rejections increase the pause to
4, 8, then at most 10 seconds. A successful reply does not cancel a pause already in effect.

This pacing applies within each batch. Separate requests and workers have independent limits;
individual sign-in and password-reset sends do not wait behind a notification batch. Rejected
messages keep their recorded failure outcome for the existing retry workflow. Lost replies and
uncertain acceptance remain pending and are never automatically resent by the batch sender.

#### Check SMTP from the image

Run this command from the app repository to check the connection, certificate, and authentication:

```bash
docker compose --env-file .env.selfhost -f docker-compose.selfhost.yml -f .local/compose.email.yml run --rm --no-deps app node dist/node-runtime/node-email-check-runtime.js
```

This check sends no message. It exits successfully when connection and authentication succeed;
it does not test sender authorization or inbox delivery. The image command needs only email
settings, so you can also use it in `docker run` without database or bucket credentials. The
reference Compose file still requires its normal database and bucket settings during parsing.
Remove the extra email Compose file argument if you use `SMTP_PASSWORD` without mounted secrets.

Optional: append `--to operator@example.edu` to send one test message. This message contains no
account access link and receives no automatic BCC. A successful send means the relay accepted
it; check the destination inbox separately. The command exits nonzero and names the setting or
connection problem when a check fails. The check does not support SES connection verification.

Mail checks are separate from API and worker readiness. CredTrail does not contact the relay on
HTTP health requests. If a relay rejects a badge notification, the badge remains issued and its
email receipt records failure. If a connection drops after sending, acceptance can be uncertain.
CredTrail never retries that send automatically; a manual retry can send a duplicate message.
If only an optional BCC recipient rejects, primary acceptance remains successful.

#### Configure SES

SES uses the existing AWS credential variables used by storage. Those credentials need SES send
permissions as well as S3 permissions. R2 API credentials cannot authenticate SES. Verify the sender
address and set:

```dotenv
EMAIL_PROVIDER=ses
AWS_SES_REGION=us-east-1
TRANSACTIONAL_EMAIL_FROM_ADDRESS=badges@example.edu
```

Optional: set `AWS_SES_CONFIGURATION_SET`. Reply-To and issuance-only BCC follow the same policy
as SMTP. Selecting a provider is explicit; CredTrail does not switch providers after a failure.

Cloudflare `EMAIL` and `AI` bindings are SaaS/Workers-only. Self-hosted installs should upload
badge artwork manually; badge image generation is unavailable until a Node AI/image provider is
added.

Validation checks:

- API health: `GET /healthz`
- Dependency readiness: `GET /healthz/dependencies`
- OB3 discovery: `GET /ims/ob/v3p0/discovery`

## Postgres Guidance

- Supported: Postgres 14+
- Recommended: managed Postgres with connection pooling (`pgBouncer` or provider equivalent)
- Backups:
  - logical backup: `pg_dump --format=custom --file=credtrail.dump "$DATABASE_URL"`
  - restore: `pg_restore --clean --if-exists --dbname "$DATABASE_URL" credtrail.dump`

## TLS Termination

Terminate TLS at your edge/load balancer (ALB, NGINX, Traefik, ingress controller).

Required forwarded headers:

- `X-Forwarded-Proto: https`
- `X-Forwarded-Host: <institution-domain>` (include the public port when it is not the default)
- `X-Forwarded-For`: append the real client address to a sanitized address chain

Set `TRUSTED_PROXY_CIDRS` to the actual socket addresses or narrow CIDRs of your controlled
proxies, for example `192.0.2.10/32,2001:db8:1::10/128` (documentation-only sample addresses).
Forwarded origin and client-IP headers are ignored by default. Trust is rooted in the socket peer;
CredTrail walks the address chain from the proxy toward the client and stops at the first untrusted
address. The proxy must overwrite forwarded protocol/host and safely append or sanitize the address
chain. Do not trust a whole shared container network that also includes clients or its client gateway.
Node ignores caller-supplied Cloudflare IP headers. The Worker runtime uses only its validated
Cloudflare edge IP. Missing transport identity uses the shared unknown rate-limit bucket.

Loopback HTTP GET/HEAD probes for `/healthz` and `/healthz/dependencies` are supported in
production Node containers even when `PUBLIC_APP_ORIGIN` uses HTTPS. Other paths and origins
retain canonical redirects. Forwarded origin normalization preserves POST bodies, cookies and
request cancellation before CSRF/authentication middleware runs.

Set `PLATFORM_DOMAIN` to the hostname used for issuer identifiers and credential identity. Do not
include a scheme, path, or port. Set `PUBLIC_APP_ORIGIN` to the one externally reachable app origin,
such as `https://credentials.example.edu`. CredTrail uses that origin for redirects, login, LTI,
emails, badge artwork, and other public app URLs; it does not infer these URLs from request headers.

## Packaged UI assets and production acceptance

The final image includes generated UI CSS, JavaScript and fonts at `/app/public/assets/ui`.
The Node adapter resolves this directory from its installed bundle, independently of the current
working directory. It serves GET/HEAD only, enforces real-path containment (including symlinks),
and returns accurate content types with `nosniff`. Content-hashed files receive immutable year-long
caching; any unversioned assets receive a bounded one-hour cache. The current font is content-hashed.
Asset responses pass through the same Hono middleware as app routes, including canonical-origin
checks, security headers, request IDs and request logging. Missing assets receive those policies too.

Run the production acceptance driver after building an image:

```bash
docker build -t credtrail-selfhost:test .
pnpm exec playwright install --with-deps chromium
node scripts/selfhost-production-smoke.mjs --image credtrail-selfhost:test
```

The driver owns disposable Postgres, S3, API/worker, network and TLS proxy resources and removes
them on exit. CI runs this same driver for the production HTTP contracts. Both API and worker
run in production on Node 24. It checks database/storage health, S3 immutable writes/read/metadata/
deletion, discovery, real login CSS/JS/fonts and their HTTP policies/logs, the browser login script,
TLS POST and CSRF behavior, spoof-resistant client IP limits, the namespace route, lifecycle jobs,
queued issuance identity and replay, and active/revoked status lists.
The driver also owns a TLS SMTP relay. It checks the packaged email command without database or
bucket credentials, follows a real production magic link, and verifies queued issuance email
acceptance and failure audits. A Postgres integration test separately captures TLS SMTP delivery
and verifies the confirmation/consumption flow and secure cookie. No real mailbox is contacted by either check.

CI also verifies both shipped Compose configurations with `scripts/selfhost-compose-smoke.mjs`.
The check uses the built image in isolated projects without published host ports. It tests the
default stack against an external disposable Postgres server with certificate-verified TLS, then
tests the optional local Postgres file. A disposable S3 emulator represents an external bucket.
The check uses only disposable credentials and does not read `.env.selfhost` or contact your cloud
services. It verifies migrations, API readiness, queue processing without a queue token, certificate
hostname rejection, database retention, and access to the same object through a normal `down`/`up`
cycle. It removes its own test resources when finished. This check does not validate a live RDS,
AWS S3, or R2 account. Run it locally after building:

```bash
node scripts/selfhost-compose-smoke.mjs --image credtrail-selfhost:test
```

Offline signature acceptance uses released `jsonld-signatures` 11.6.0, `@digitalbazaar/data-integrity`
2.5.0 and `@digitalbazaar/eddsa-rdfc-2022-cryptosuite` 1.3.0 as test-only dependencies. Base and
full TrustEd fixtures use authoritative VC v2, OB3 3.0.3 and status v1 context documents with SHA-256
provenance under `packages/core-domain/src/contexts`; tests also reject altered signed content.

The extension vocabulary identifier remains `https://credtrail.org/ns/trusted-credential/v1` on
self-hosted credentials. The app provides an unauthenticated GET/HEAD route returning its signing
context as `application/ld+json` with public caching and an ETag. After an authorized release, verify
that the canonical public URL serves that same document; local smoke success does not establish
public deployment. Do not rewrite existing immutable signed credentials.

## Upgrade Procedure (Image Tag N -> N+1)

1. Pull new image tag:
   - `docker pull ghcr.io/longsightgroup/credtrail-app:<N+1>`
2. Run database migrations before switching traffic:
   - Use the `migrate` service pattern from `docker-compose.selfhost.yml`.
3. Start new app + worker containers with identical env vars.
4. Confirm:
   - `GET /healthz/dependencies` returns `200`.
   - queue worker logs show successful `node_queue_worker_tick` events.
5. Shift traffic to new app container.
6. Keep previous image tag `<N>` available for rollback.

## Rollback Procedure

1. Stop the `<N+1>` app and worker containers.
2. Start containers using previous tag `<N>`.
3. Verify `/healthz/dependencies`.
4. If migration incompatibility is discovered, restore from backup made before upgrade.

## Troubleshooting

- `DATABASE_URL is required`:
  - missing/empty env var; verify secret injection.
- Postgres connection refused / timeout:
  - database host unreachable or firewall block.
  - verify DNS, network policies, and TLS mode for managed Postgres.
- `S3_BUCKET is required` or `AWS_ACCESS_KEY_ID is required`:
  - required object storage env var missing.
- storage dependency check returns 503:
  - verify `S3_ENDPOINT`, credentials, bucket existence, and path-style config.
- queue worker logs `node_queue_worker_error`:
  - inspect the logged `detail` field, then verify database/storage credentials
    and queued job payloads.
  - the Node queue worker processes jobs in-process; it does not call
    `/v1/jobs/process` or use `JOB_PROCESSOR_TOKEN`.
- migration failures:
  - run migrations with `-v ON_ERROR_STOP=1` and inspect the first failing statement.
