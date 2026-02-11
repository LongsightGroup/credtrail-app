# OB3 Certification Runbook

This runbook operationalizes `badging-9le` for 1EdTech Open Badges 3.0 Issuer certification.

## Goal

Complete certification submission with reproducible evidence:

1. Issue a valid OB3 badge to `conformance@imsglobal.org`
2. Submit to 1EdTech conformance test tooling
3. Record recipient retrieval video
4. Pass required tests
5. Collect approval artifacts

## Prerequisites

- A deployed `credtrail-app` environment reachable by HTTPS.
- Admin bootstrap token configured in the deployment (`BOOTSTRAP_ADMIN_TOKEN`).
- Job processing route reachable (`/v1/jobs/process`) and token if required.
- OB3 conformance checklist baseline complete:
  - `credtrail-private/docs/ob-v3p0-conformance-checklist.md`
- Internal confirmation of 1EdTech membership and tester access.

## Automated Preflight

Run from repo root:

```bash
pnpm cert:preflight
```

This runs:

- `pnpm lint`
- `pnpm typecheck`
- `pnpm test -- apps/api-worker/src/index.test.ts`

Optional live issuance smoke test:

```bash
CERT_BASE_URL="https://<deployment-host>" \
CERT_BOOTSTRAP_ADMIN_TOKEN="<token>" \
CERT_JOB_PROCESSOR_TOKEN="<optional-token>" \
pnpm cert:preflight
```

Live mode will:

- Generate signing key material
- Upsert a certification tenant and signing registration
- Upsert a certification badge template
- Queue issuance to `conformance@imsglobal.org`
- Process queue jobs
- Verify `GET /credentials/v1/:credentialId` returns active/valid checks
- Save evidence JSON at `artifacts/ob3-certification/preflight-*.json`

## Manual Certification Steps

1. Confirm the issued test credential URLs from the preflight artifact:
   - verification URL
   - JSON-LD URL
   - download URL
   - public badge URL
2. Submit issued badge evidence in the 1EdTech conformance system.
3. Run required issuer conformance suites.
4. Record recipient retrieval methodology video.

Video should show:

- How recipient receives the badge
- How recipient accesses the credential URL
- Verification endpoint output
- Revocation/expiration handling visibility (where applicable)

## Evidence Bundle Checklist

Store in `artifacts/ob3-certification/` (or equivalent secure location):

- Preflight JSON report(s)
- Submitted credential payload and URL
- Conformance test run report exports
- Video recording file and transcript/notes
- Final approval confirmation and logo/license artifacts

## Completion Criteria Mapping

- Badge issued and validated: preflight live evidence + conformance submission record.
- Video recorded and accepted: stored recording + reviewer sign-off.
- Submission successful: test system result export.
- Certification approval: official confirmation artifact collected.
