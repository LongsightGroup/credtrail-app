import {
  createAuditLog,
  createMagicLinkToken,
  createSession,
  ensureTenantMembership,
  findMagicLinkTokenByHash,
  isMagicLinkTokenValid,
  markMagicLinkTokenUsed,
  revokeSessionByHash,
  upsertUserByEmail,
  type SessionRecord,
  type SqlDatabase,
} from '@credtrail/db';
import { renderPageShell } from '@credtrail/ui-components';
import type { Hono } from 'hono';
import { deleteCookie, getCookie, setCookie } from 'hono/cookie';
import { parseMagicLinkRequest, parseMagicLinkVerifyRequest } from '@credtrail/validation';
import type { AppBindings, AppContext, AppEnv } from '../app';

interface RegisterAuthRoutesInput {
  app: Hono<AppEnv>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  resolveSessionFromCookie: (c: AppContext) => Promise<SessionRecord | null>;
  addSecondsToIso: (isoTimestamp: string, seconds: number) => string;
  generateOpaqueToken: () => string;
  sha256Hex: (value: string) => Promise<string>;
  sessionCookieSecure: (appEnv: string) => boolean;
  MAGIC_LINK_TTL_SECONDS: number;
  SESSION_TTL_SECONDS: number;
  SESSION_COOKIE_NAME: string;
}

export const registerAuthRoutes = (input: RegisterAuthRoutesInput): void => {
  const {
    app,
    resolveDatabase,
    resolveSessionFromCookie,
    addSecondsToIso,
    generateOpaqueToken,
    sha256Hex,
    sessionCookieSecure,
    MAGIC_LINK_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    SESSION_COOKIE_NAME,
  } = input;

  app.get('/', (c) => {
    return c.html(
      renderPageShell(
        'CredTrail',
        `<h1>CredTrail</h1><p>Cloudflare Worker API + server-rendered interface scaffold for ${c.env.PLATFORM_DOMAIN}.</p>`,
      ),
    );
  });

  app.post('/v1/auth/magic-link/request', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseMagicLinkRequest(payload);
    const nowIso = new Date().toISOString();
    const expiresAt = addSecondsToIso(nowIso, MAGIC_LINK_TTL_SECONDS);
    const user = await upsertUserByEmail(resolveDatabase(c.env), request.email);
    const membershipResult = await ensureTenantMembership(
      resolveDatabase(c.env),
      request.tenantId,
      user.id,
    );

    if (membershipResult.created) {
      await createAuditLog(resolveDatabase(c.env), {
        tenantId: request.tenantId,
        actorUserId: user.id,
        action: 'membership.role_assigned',
        targetType: 'membership',
        targetId: `${request.tenantId}:${user.id}`,
        metadata: {
          userId: user.id,
          role: membershipResult.membership.role,
        },
      });
    }

    const magicLinkToken = generateOpaqueToken();
    const magicTokenHash = await sha256Hex(magicLinkToken);

    await createMagicLinkToken(resolveDatabase(c.env), {
      tenantId: request.tenantId,
      userId: user.id,
      magicTokenHash,
      expiresAt,
    });

    if (c.env.APP_ENV === 'development') {
      return c.json(
        {
          status: 'sent',
          tenantId: request.tenantId,
          email: request.email,
          expiresAt,
          magicLinkToken,
        },
        202,
      );
    }

    return c.json(
      {
        status: 'sent',
        tenantId: request.tenantId,
        email: request.email,
        expiresAt,
      },
      202,
    );
  });

  app.post('/v1/auth/magic-link/verify', async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseMagicLinkVerifyRequest(payload);
    const nowIso = new Date().toISOString();
    const magicTokenHash = await sha256Hex(request.token);
    const token = await findMagicLinkTokenByHash(resolveDatabase(c.env), magicTokenHash);

    if (token === null || !isMagicLinkTokenValid(token, nowIso)) {
      return c.json(
        {
          error: 'Invalid or expired magic link token',
        },
        400,
      );
    }

    await markMagicLinkTokenUsed(resolveDatabase(c.env), token.id, nowIso);

    const sessionToken = generateOpaqueToken();
    const sessionTokenHash = await sha256Hex(sessionToken);
    const session = await createSession(resolveDatabase(c.env), {
      tenantId: token.tenantId,
      userId: token.userId,
      sessionTokenHash,
      expiresAt: addSecondsToIso(nowIso, SESSION_TTL_SECONDS),
    });

    setCookie(c, SESSION_COOKIE_NAME, sessionToken, {
      httpOnly: true,
      secure: sessionCookieSecure(c.env.APP_ENV),
      sameSite: 'Lax',
      path: '/',
      maxAge: SESSION_TTL_SECONDS,
    });

    return c.json({
      status: 'authenticated',
      tenantId: session.tenantId,
      userId: session.userId,
      expiresAt: session.expiresAt,
    });
  });

  app.get('/v1/auth/session', async (c) => {
    const session = await resolveSessionFromCookie(c);

    if (session === null) {
      return c.json(
        {
          error: 'Not authenticated',
        },
        401,
      );
    }

    return c.json({
      status: 'authenticated',
      tenantId: session.tenantId,
      userId: session.userId,
      expiresAt: session.expiresAt,
    });
  });

  app.post('/v1/auth/logout', async (c) => {
    const sessionToken = getCookie(c, SESSION_COOKIE_NAME);

    if (sessionToken !== undefined) {
      const sessionTokenHash = await sha256Hex(sessionToken);
      await revokeSessionByHash(resolveDatabase(c.env), sessionTokenHash, new Date().toISOString());
    }

    deleteCookie(c, SESSION_COOKIE_NAME, {
      path: '/',
    });

    return c.json({
      status: 'signed_out',
    });
  });
};
