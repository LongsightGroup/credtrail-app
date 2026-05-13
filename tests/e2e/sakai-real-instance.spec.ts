import {
  type APIRequestContext,
  type APIResponse,
  expect,
  type Locator,
  type Page,
  test,
} from '@playwright/test';

interface BootstrapTenantResponse {
  tenant?: {
    id: string;
  };
}

interface BootstrapRegistrationResponse {
  registration?: {
    issuer: string;
    tenantId: string;
    clientId: string;
    platformJwksEndpoint: string | null;
    tokenEndpoint: string | null;
  };
}

const parseBoolean = (value: string | undefined, defaultValue: boolean): boolean => {
  if (value === undefined) {
    return defaultValue;
  }

  const normalized = value.trim().toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes';
};

const firstVisibleLocator = async (locators: readonly Locator[]): Promise<Locator | null> => {
  for (const locator of locators) {
    const candidate = locator.first();
    const visible = await candidate.isVisible().catch(() => false);

    if (visible) {
      return candidate;
    }
  }

  return null;
};

const decodeJsonBody = async <T>(response: APIResponse): Promise<T> => {
  const textBody = await response.text();
  const status = response.status();

  if (status < 200 || status >= 300) {
    throw new Error(`Unexpected response status ${String(status)}: ${textBody}`);
  }

  return JSON.parse(textBody) as T;
};

const requireNonEmptyEnv = (name: string, value: string): string => {
  expect(value, `${name} is required for real Sakai e2e`).not.toBe('');
  return value;
};

const realSakaiEnabled = parseBoolean(process.env.E2E_REAL_SAKAI_ENABLED, false);
const adminToken = process.env.E2E_BOOTSTRAP_ADMIN_TOKEN?.trim() ?? '';
const sakaiTenantId = process.env.E2E_SAKAI_TENANT_ID?.trim() ?? '';
const sakaiIssuer = process.env.E2E_SAKAI_ISSUER?.trim() ?? '';
const sakaiAuthorizationEndpoint = process.env.E2E_SAKAI_AUTHORIZATION_ENDPOINT?.trim() ?? '';
const sakaiClientId = process.env.E2E_SAKAI_CLIENT_ID?.trim() ?? '';
const sakaiTargetLinkUri = process.env.E2E_SAKAI_TARGET_LINK_URI?.trim() ?? '';
const sakaiLoginHint = process.env.E2E_SAKAI_LOGIN_HINT?.trim() ?? '';
const sakaiDeploymentId = process.env.E2E_SAKAI_DEPLOYMENT_ID?.trim() ?? '';
const sakaiPlatformJwksEndpoint = process.env.E2E_SAKAI_PLATFORM_JWKS_ENDPOINT?.trim() ?? '';
const sakaiTokenEndpoint = process.env.E2E_SAKAI_TOKEN_ENDPOINT?.trim() ?? '';
const sakaiUsername = process.env.E2E_SAKAI_USERNAME?.trim() ?? '';
const sakaiPassword = process.env.E2E_SAKAI_PASSWORD?.trim() ?? '';
const requireDeepLinking = parseBoolean(process.env.E2E_SAKAI_REQUIRE_DEEP_LINKING, false);
const requireNrps = parseBoolean(process.env.E2E_SAKAI_REQUIRE_NRPS, false);
const expectedRole = (process.env.E2E_SAKAI_EXPECTED_ROLE?.trim().toLowerCase() ?? 'any') as
  | 'any'
  | 'instructor'
  | 'learner';

const ensureTenant = async (request: APIRequestContext): Promise<void> => {
  const tenantResponse = await request.put(`/v1/admin/tenants/${encodeURIComponent(sakaiTenantId)}`, {
    headers: {
      authorization: `Bearer ${adminToken}`,
    },
    data: {
      slug: sakaiTenantId,
      displayName: `Sakai Tenant ${sakaiTenantId}`,
      planTier: 'team',
      isActive: true,
    },
  });

  const tenantPayload = await decodeJsonBody<BootstrapTenantResponse>(tenantResponse);
  expect(tenantPayload.tenant?.id).toBe(sakaiTenantId);
};

const upsertIssuerRegistration = async (request: APIRequestContext): Promise<void> => {
  const registrationResponse = await request.put('/v1/admin/lti/issuer-registrations', {
    headers: {
      authorization: `Bearer ${adminToken}`,
      'content-type': 'application/json',
    },
    data: {
      issuer: sakaiIssuer,
      tenantId: sakaiTenantId,
      authorizationEndpoint: sakaiAuthorizationEndpoint,
      clientId: sakaiClientId,
      platformJwksEndpoint: sakaiPlatformJwksEndpoint,
      tokenEndpoint: sakaiTokenEndpoint,
    },
  });

  const registrationPayload = await decodeJsonBody<BootstrapRegistrationResponse>(registrationResponse);
  expect(registrationPayload.registration?.issuer).toBe(sakaiIssuer);
  expect(registrationPayload.registration?.tenantId).toBe(sakaiTenantId);
  expect(registrationPayload.registration?.clientId).toBe(sakaiClientId);
  expect(registrationPayload.registration?.platformJwksEndpoint).toBe(sakaiPlatformJwksEndpoint);
  expect(registrationPayload.registration?.tokenEndpoint).toBe(sakaiTokenEndpoint);
};

const maybeCompleteSakaiLogin = async ({
  page,
}: {
  page: Page;
}): Promise<void> => {
  const usernameField = await firstVisibleLocator([
    page.locator('input[name="eid"]'),
    page.locator('input#eid'),
    page.locator('input[name="username"]'),
    page.locator('input#username'),
    page.locator('input[name="j_username"]'),
    page.locator('input#j_username'),
  ]);

  if (usernameField === null) {
    return;
  }

  expect(sakaiUsername, 'Sakai login form detected but E2E_SAKAI_USERNAME is not set').not.toBe('');
  expect(sakaiPassword, 'Sakai login form detected but E2E_SAKAI_PASSWORD is not set').not.toBe('');

  await usernameField.fill(sakaiUsername);

  const passwordField = await firstVisibleLocator([
    page.locator('input[name="pw"]'),
    page.locator('input#pw'),
    page.locator('input[name="password"]'),
    page.locator('input#password'),
    page.locator('input[name="j_password"]'),
    page.locator('input#j_password'),
    page.locator('input[type="password"]'),
  ]);

  expect(passwordField, 'Could not find Sakai password field on login page').not.toBeNull();
  await passwordField!.fill(sakaiPassword);

  const submitButton = await firstVisibleLocator([
    page.locator('button[type="submit"]'),
    page.locator('input[type="submit"]'),
    page.getByRole('button', { name: /log in|login|sign in/i }),
  ]);

  expect(submitButton, 'Could not find a submit button on Sakai login page').not.toBeNull();
  await Promise.all([
    page.waitForLoadState('domcontentloaded'),
    submitButton!.click(),
  ]);
};

const resolveCredTrailLtiView = async ({
  page,
}: {
  page: Page;
}): Promise<'launch' | 'deep-link' | null> => {
  const launchHeading = page.getByRole('heading', { name: 'LTI 1.3 launch complete' });

  if (await launchHeading.isVisible().catch(() => false)) {
    return 'launch';
  }

  const deepLinkHeading = page.getByRole('heading', { name: 'Select badge template placement' });

  if (await deepLinkHeading.isVisible().catch(() => false)) {
    return 'deep-link';
  }

  return null;
};

test('real Sakai launch reaches CredTrail and handles available capabilities @real-sakai', async ({
  page,
  request,
}) => {
  test.skip(
    !realSakaiEnabled,
    'Set E2E_REAL_SAKAI_ENABLED=true with Sakai env vars to run real-instance validation.',
  );

  const resolvedAdminToken = requireNonEmptyEnv('E2E_BOOTSTRAP_ADMIN_TOKEN', adminToken);
  const resolvedTenantId = requireNonEmptyEnv('E2E_SAKAI_TENANT_ID', sakaiTenantId);
  const resolvedIssuer = requireNonEmptyEnv('E2E_SAKAI_ISSUER', sakaiIssuer);
  const resolvedAuthorizationEndpoint = requireNonEmptyEnv(
    'E2E_SAKAI_AUTHORIZATION_ENDPOINT',
    sakaiAuthorizationEndpoint,
  );
  const resolvedClientId = requireNonEmptyEnv('E2E_SAKAI_CLIENT_ID', sakaiClientId);
  const resolvedTargetLinkUri = requireNonEmptyEnv('E2E_SAKAI_TARGET_LINK_URI', sakaiTargetLinkUri);
  const resolvedLoginHint = requireNonEmptyEnv('E2E_SAKAI_LOGIN_HINT', sakaiLoginHint);
  requireNonEmptyEnv('E2E_SAKAI_PLATFORM_JWKS_ENDPOINT', sakaiPlatformJwksEndpoint);
  requireNonEmptyEnv('E2E_SAKAI_TOKEN_ENDPOINT', sakaiTokenEndpoint);

  expect(expectedRole === 'any' || expectedRole === 'instructor' || expectedRole === 'learner').toBe(
    true,
  );

  await ensureTenant(request);
  await upsertIssuerRegistration(request);

  const loginQuery = new URLSearchParams({
    iss: resolvedIssuer,
    login_hint: resolvedLoginHint,
    target_link_uri: resolvedTargetLinkUri,
    client_id: resolvedClientId,
  });

  if (sakaiDeploymentId.length > 0) {
    loginQuery.set('lti_deployment_id', sakaiDeploymentId);
  }

  await page.goto(`/v1/lti/oidc/login?${loginQuery.toString()}`);

  await maybeCompleteSakaiLogin({ page });

  await expect
    .poll(() => resolveCredTrailLtiView({ page }), {
      timeout: 45_000,
      message: 'Expected CredTrail LTI launch result or deep-link selection page after Sakai launch',
    })
    .not.toBeNull();

  const resolvedView = await resolveCredTrailLtiView({ page });
  expect(resolvedView).not.toBeNull();

  if (resolvedView === 'deep-link') {
    if (requireNrps) {
      throw new Error(
        'E2E_SAKAI_REQUIRE_NRPS=true cannot be satisfied from a deep-link launch; use a resource-link placement.',
      );
    }

    expect(requireDeepLinking, 'Expected deep-link launch but E2E_SAKAI_REQUIRE_DEEP_LINKING=false').toBe(
      true,
    );
    await expect(page.getByText('Choose a badge template and return it to your LMS via LTI Deep Linking.')).toBeVisible();
    return;
  }

  expect(requireDeepLinking, 'Expected deep-link launch but observed resource-link launch').toBe(false);

  const launchHero = page.locator('.lti-launch__hero p');
  await expect(launchHero).toBeVisible();

  const launchHeroText = (await launchHero.textContent()) ?? '';

  if (expectedRole === 'instructor') {
    expect(launchHeroText).toContain('Instructor');
  } else if (expectedRole === 'learner') {
    expect(launchHeroText).toContain('Learner');
  }

  await expect(page.getByText('Message type')).toBeVisible();

  const bulkSection = page.locator('.lti-launch__bulk-title');

  if (requireNrps) {
    await expect(bulkSection).toBeVisible();
    await expect(page.locator('.lti-launch__bulk-status--ready')).toBeVisible();
    return;
  }

  const hasBulkSection = await bulkSection.isVisible().catch(() => false);

  if (hasBulkSection) {
    const hasReady = await page.locator('.lti-launch__bulk-status--ready').isVisible().catch(() => false);
    const hasUnavailable = await page
      .locator('.lti-launch__bulk-status--unavailable')
      .isVisible()
      .catch(() => false);
    const hasError = await page.locator('.lti-launch__bulk-status--error').isVisible().catch(() => false);

    expect(hasReady || hasUnavailable || hasError).toBe(true);
  }
});
