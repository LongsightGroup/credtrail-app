# Self-Hosted Docker Runbook

This runbook covers institutional self-host deployment for CredTrail using Docker, Postgres, and
S3-compatible object storage.

## Runtime Profile

- API runtime: Node (`apps/api-worker/src/node-server.ts`)
- Queue worker: Node polling process (`apps/api-worker/src/node-worker.ts`)
- Database: Postgres 14+
- Object storage: S3-compatible API (AWS S3, MinIO, Ceph RGW, etc.)
- Production installs must run with `APP_ENV=production`. The Docker image defaults to
  production, and the reference compose stack sets `APP_ENV=production`.

## Required Environment Variables

- `DATABASE_URL`
- `S3_BUCKET`
- `S3_REGION`
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `S3_ENDPOINT` (required for non-AWS providers)
- `S3_FORCE_PATH_STYLE` (`true` for MinIO/Ceph path-style deployments)
- `PLATFORM_DOMAIN`
- `APP_ENV`
- `BETTER_AUTH_SECRET` (stable, high-entropy secret; rotate only with a session reset plan)
- `BETTER_AUTH_TRUSTED_ORIGINS` (comma-separated public origins allowed to use hosted auth)
- `PORT`

Optional:

- `JOB_PROCESSOR_TOKEN`
- `AWS_SESSION_TOKEN`
- `EMAIL_PROVIDER` (`ses` for AWS SES, or omit to disable outbound email)
- `AWS_SES_REGION` (defaults to `S3_REGION` if omitted)
- `TRANSACTIONAL_EMAIL_FROM_ADDRESS` (required when `EMAIL_PROVIDER=ses`)
- `AWS_SES_CONFIGURATION_SET`
- `SENTRY_DSN`

Worker notes:

- The worker process runs the same queue-processing route logic in-process.
- Configure worker containers with the same DB/storage credentials as the API container.

## Local Validation with Docker Compose

Use the provided compose stack to validate the self-host production runtime locally:

```bash
docker compose -f docker-compose.selfhost.yml up --build
```

The compose stack intentionally leaves outbound email disabled. This keeps local validation from
pretending to send mail with fake AWS credentials.

Do not use `APP_ENV=development` for real self-host installs. Development mode enables local
debugging behavior such as single-use database connections and development auth shortcuts.

Before using the compose stack beyond local validation, replace the sample `BETTER_AUTH_SECRET`
with a stable random value and set `BETTER_AUTH_TRUSTED_ORIGINS` to the public HTTPS origin for
the deployment.

For outbound email, the Node self-host runtime supports `EMAIL_PROVIDER=ses`. Configure AWS
credentials with SES send permissions and verify `TRANSACTIONAL_EMAIL_FROM_ADDRESS` in SES before
enabling magic-link, password-reset, invite, or issuance emails. If `EMAIL_PROVIDER` is omitted,
email delivery is a silent no-op.

Production SES example:

```yaml
EMAIL_PROVIDER: ses
AWS_SES_REGION: us-east-1
TRANSACTIONAL_EMAIL_FROM_ADDRESS: no-reply@example.edu
```

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
- `X-Forwarded-Host: <institution-domain>`

Set `PLATFORM_DOMAIN` to the public hostname used in credential URLs.

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
