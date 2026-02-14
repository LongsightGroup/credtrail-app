import { describe, expect, it, vi } from 'vitest';
import { app } from './index';
import type { AppBindings } from './app';
import type { JsonObject } from '@credtrail/core-domain';

const asJsonObject = (value: unknown): JsonObject | null => {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as JsonObject)
    : null;
};

const asString = (value: unknown): string | null => {
  return typeof value === 'string' ? value : null;
};

const createEnv = (): AppBindings => {
  return {
    APP_ENV: 'test',
    PLATFORM_DOMAIN: 'credtrail.test',
    BADGE_OBJECTS: {} as R2Bucket,
  };
};

describe('marketing landing proxy', () => {
  it('proxies root requests to MARKETING_SITE_ORIGIN when configured', async () => {
    const env = {
      ...createEnv(),
      MARKETING_SITE_ORIGIN: 'https://marketing.credtrail.test',
    };
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('<html>landing</html>', {
        status: 200,
        headers: {
          'content-type': 'text/html; charset=UTF-8',
        },
      }),
    );

    const response = await app.fetch(new Request('https://credtrail.test/'), env);
    const body = await response.text();

    expect(response.status).toBe(200);
    expect(body).toContain('landing');

    const firstCall = fetchSpy.mock.calls[0];
    const firstRequest = firstCall?.[0];

    expect(firstRequest).toBeInstanceOf(Request);
    if (!(firstRequest instanceof Request)) {
      throw new Error('Expected first fetch argument to be a Request');
    }
    expect(firstRequest.url).toBe('https://marketing.credtrail.test/');

    fetchSpy.mockRestore();
  });
});

describe('canonical host redirects', () => {
  it('redirects www host requests to the canonical platform domain', async () => {
    const env = createEnv();
    const response = await app.fetch(
      new Request('https://www.credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test'),
      env,
    );

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe(
      'https://credtrail.test/badges/40a6dc92-85ec-4cb0-8a50-afb2ae700e22?utm=test',
    );
  });

  it('redirects legacy badges subdomain requests to the canonical platform domain', async () => {
    const env = createEnv();
    const response = await app.fetch(new Request('https://badges.credtrail.test/healthz'), env);

    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('https://credtrail.test/healthz');
  });
});

describe('GET /ims/ob/v3p0/discovery', () => {
  it('returns a public OB3 service description document with OAuth metadata', async () => {
    const env = createEnv();
    const response = await app.fetch(new Request('https://credtrail.test/ims/ob/v3p0/discovery'), env);
    const body = await response.json<JsonObject>();

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toContain('application/json');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(asString(body.openapi)).toBe('3.0.1');

    const info = asJsonObject(body.info);
    expect(asString(info?.title)).toBe('CredTrail Open Badges API');
    expect(asString(info?.termsOfService)).toBe('https://credtrail.test/terms');
    expect(asString(info?.['x-imssf-privacyPolicyUrl'])).toBe('https://credtrail.test/privacy');
    expect(asString(info?.['x-imssf-image'])).toBe('https://credtrail.test/credtrail-logo.png');

    const servers = body.servers;
    expect(Array.isArray(servers)).toBe(true);
    const firstServer =
      Array.isArray(servers) && servers.length > 0 && typeof servers[0] === 'object'
        ? asJsonObject(servers[0])
        : null;
    expect(asString(firstServer?.url)).toBe('https://credtrail.test/ims/ob/v3p0');

    const paths = asJsonObject(body.paths);
    expect(asJsonObject(paths?.['/discovery'])).not.toBeNull();
    expect(asJsonObject(paths?.['/credentials'])).not.toBeNull();
    expect(asJsonObject(paths?.['/profile'])).not.toBeNull();

    const components = asJsonObject(body.components);
    const securitySchemes = asJsonObject(components?.securitySchemes);
    const oauthScheme = asJsonObject(securitySchemes?.OAuth2ACG);
    expect(asString(oauthScheme?.type)).toBe('oauth2');
    expect(asString(oauthScheme?.['x-imssf-registrationUrl'])).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/register',
    );

    const flows = asJsonObject(oauthScheme?.flows);
    const authorizationCode = asJsonObject(flows?.authorizationCode);
    expect(asString(authorizationCode?.authorizationUrl)).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/authorize',
    );
    expect(asString(authorizationCode?.tokenUrl)).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/token',
    );
    expect(asString(authorizationCode?.refreshUrl)).toBe(
      'https://credtrail.test/ims/ob/v3p0/oauth/refresh',
    );

    const scopes = asJsonObject(authorizationCode?.scopes);
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.readonly']),
    ).toContain('Permission');
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/credential.upsert']),
    ).toContain('Permission');
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.readonly']),
    ).toContain('Permission');
    expect(
      asString(scopes?.['https://purl.imsglobal.org/spec/ob/v3p0/scope/profile.update']),
    ).toContain('Permission');
  });
});
