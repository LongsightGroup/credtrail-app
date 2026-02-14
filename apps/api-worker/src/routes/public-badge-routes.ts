import { listPublicBadgeWallEntries, type SqlDatabase } from '@credtrail/db';
import type { Hono } from 'hono';
import { parseTenantPathParams } from '@credtrail/validation';
import type { AppBindings, AppEnv } from '../app';

interface RegisterPublicBadgeRoutesInput<PublicBadgeValue> {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  loadPublicBadgeViewModel: (
    db: SqlDatabase,
    badgeObjects: R2Bucket,
    badgeIdentifier: string,
  ) => Promise<
    | {
        status: 'not_found';
      }
    | {
        status: 'redirect';
        canonicalPath: string;
      }
    | {
        status: 'ok';
        value: PublicBadgeValue;
      }
  >;
  publicBadgeNotFoundPage: () => string;
  publicBadgePage: (requestUrl: string, value: PublicBadgeValue) => string;
  tenantBadgeWallPage: (
    requestUrl: string,
    tenantId: string,
    entries: Awaited<ReturnType<typeof listPublicBadgeWallEntries>>,
    badgeTemplateId: string | null,
  ) => string;
  asNonEmptyString: (value: unknown) => string | null;
  SAKAI_SHOWCASE_TENANT_ID: string;
  SAKAI_SHOWCASE_TEMPLATE_ID: string;
}

export const registerPublicBadgeRoutes = <PublicBadgeValue>(
  input: RegisterPublicBadgeRoutesInput<PublicBadgeValue>,
): void => {
  const {
    app,
    resolveDatabase,
    loadPublicBadgeViewModel,
    publicBadgeNotFoundPage,
    publicBadgePage,
    tenantBadgeWallPage,
    asNonEmptyString,
    SAKAI_SHOWCASE_TENANT_ID,
    SAKAI_SHOWCASE_TEMPLATE_ID,
  } = input;

  app.get('/badges/:badgeIdentifier/public_url', (c) => {
    const badgeIdentifier = c.req.param('badgeIdentifier').trim();

    if (badgeIdentifier.length === 0) {
      return c.html(publicBadgeNotFoundPage(), 404);
    }

    return c.redirect(`/badges/${encodeURIComponent(badgeIdentifier)}`, 308);
  });

  app.get('/badges/:badgeIdentifier', async (c) => {
    const badgeIdentifier = c.req.param('badgeIdentifier');
    const result = await loadPublicBadgeViewModel(
      resolveDatabase(c.env),
      c.env.BADGE_OBJECTS,
      badgeIdentifier,
    );

    c.header('Cache-Control', 'no-store');

    if (result.status === 'not_found') {
      return c.html(publicBadgeNotFoundPage(), 404);
    }

    if (result.status === 'redirect') {
      return c.redirect(result.canonicalPath, 308);
    }

    return c.html(publicBadgePage(c.req.url, result.value));
  });

  app.get('/showcase/:tenantId', async (c) => {
    const pathParams = parseTenantPathParams(c.req.param());
    const requestedBadgeTemplateId = asNonEmptyString(c.req.query('badgeTemplateId'));
    const badgeTemplateId =
      requestedBadgeTemplateId ??
      (pathParams.tenantId === SAKAI_SHOWCASE_TENANT_ID ? SAKAI_SHOWCASE_TEMPLATE_ID : null);
    const entries = await listPublicBadgeWallEntries(resolveDatabase(c.env), {
      tenantId: pathParams.tenantId,
      ...(badgeTemplateId === null ? {} : { badgeTemplateId }),
    });
    c.header('Cache-Control', 'no-store');
    return c.html(tenantBadgeWallPage(c.req.url, pathParams.tenantId, entries, badgeTemplateId));
  });
};
