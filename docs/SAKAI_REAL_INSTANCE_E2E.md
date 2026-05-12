# Sakai Real-Instance E2E Validation

This runbook defines the `badging-2ky` validation path: execute a live end-to-end
LTI 1.3 launch against a real Sakai environment and verify CredTrail launch behavior.

## What this test validates

The Playwright test `tests/e2e/sakai-real-instance.spec.ts` validates:

1. CredTrail can bootstrap a tenant and issuer registration through admin APIs.
2. CredTrail OIDC login initiation can redirect into Sakai launch flow.
3. A real Sakai launch can return to CredTrail launch UI or deep-link UI.
4. Optional capability expectations can be enforced:
   - deep linking required (`E2E_SAKAI_REQUIRE_DEEP_LINKING=true`)
   - NRPS-ready bulk roster status required (`E2E_SAKAI_REQUIRE_NRPS=true`)
   - expected launch role (`E2E_SAKAI_EXPECTED_ROLE=instructor|learner`)

This test is intentionally gated and skipped by default in standard CI.

## Prerequisites

1. A reachable CredTrail environment and valid `E2E_BOOTSTRAP_ADMIN_TOKEN`.
2. A Sakai tool registration configured for CredTrail:
   - matching `issuer` (`iss`)
   - matching `client_id`
   - valid OIDC authorization endpoint
   - platform JWKS endpoint for signed launch verification
   - token endpoint for LTI Advantage service calls
   - tool launch URL set to CredTrail target link URI
3. Optional Sakai username/password if Sakai shows an interactive login page.
4. For NRPS-required assertions, Sakai roster access must be enabled and token flow configured.

## Local execution

Run from repository root:

```bash
E2E_BASE_URL="https://credtrail.org" \
E2E_REAL_SAKAI_ENABLED="true" \
E2E_BOOTSTRAP_ADMIN_TOKEN="<bootstrap-admin-token>" \
E2E_SAKAI_TENANT_ID="sakai" \
E2E_SAKAI_ISSUER="https://sakai.example" \
E2E_SAKAI_AUTHORIZATION_ENDPOINT="https://sakai.example/imsoidc/lti13/oidc_auth" \
E2E_SAKAI_CLIENT_ID="<lti-client-id>" \
E2E_SAKAI_TARGET_LINK_URI="https://credtrail.org/v1/lti/launch" \
E2E_SAKAI_LOGIN_HINT="<sakai-login-hint>" \
E2E_SAKAI_DEPLOYMENT_ID="<optional-deployment-id>" \
E2E_SAKAI_PLATFORM_JWKS_ENDPOINT="https://sakai.example/imsoidc/lti13/jwks" \
E2E_SAKAI_TOKEN_ENDPOINT="https://sakai.example/imsoidc/lti13/token" \
E2E_SAKAI_USERNAME="<optional-sakai-username>" \
E2E_SAKAI_PASSWORD="<optional-sakai-password>" \
E2E_SAKAI_REQUIRE_DEEP_LINKING="false" \
E2E_SAKAI_REQUIRE_NRPS="false" \
E2E_SAKAI_EXPECTED_ROLE="any" \
pnpm test:e2e:sakai-real --project=chromium
```

## GitHub Actions execution

Use workflow: `.github/workflows/sakai-real-e2e.yml`

Inputs:

1. `base_url`
2. `tenant_id`
3. `sakai_issuer`
4. `sakai_authorization_endpoint`
5. `sakai_client_id`
6. `sakai_target_link_uri`
7. `sakai_login_hint`
8. optional `sakai_deployment_id`
9. `sakai_platform_jwks_endpoint`
10. `sakai_token_endpoint`
11. optional `require_deep_linking`
12. optional `require_nrps`
13. optional `expected_role`
14. optional `sakai_username`

Required repository secret:

- `E2E_BOOTSTRAP_ADMIN_TOKEN`

Optional repository secrets:

- `E2E_SAKAI_PASSWORD` (required when `sakai_username` is provided)

## Failure triage

Common failures:

1. `401`/`403` from admin bootstrap endpoints due invalid `E2E_BOOTSTRAP_ADMIN_TOKEN`.
2. OIDC initiation errors due issuer/client/authorization endpoint mismatch.
3. Launch never returns to CredTrail because Sakai tool placement or target link URI is misconfigured.
4. `E2E_SAKAI_REQUIRE_DEEP_LINKING=true` but launch returns resource-link flow.
5. `E2E_SAKAI_REQUIRE_NRPS=true` but roster capability is disabled in Sakai or token settings are incomplete.
6. Signed launch verification fails because the platform JWKS endpoint is missing or does not expose the active Sakai signing key.

When failures occur:

1. Verify Sakai tool config values match workflow/local env values exactly.
2. Re-run with `require_nrps=false` and `require_deep_linking=false` to establish baseline launch.
3. Confirm Sakai-side capabilities (`allowroster`, deep-link launch placement) are enabled for the tool.
4. Confirm any required Sakai account credentials were provided for interactive login prompts.
