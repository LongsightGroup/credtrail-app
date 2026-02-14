import type { JsonObject } from '@credtrail/core-domain';
import type { Hono } from 'hono';
import type { TenantSigningRegistryEntry } from '@credtrail/validation';
import type { AppContext, AppEnv } from '../app';

interface SigningKeyLike {
  keyId: string;
  publicJwk: TenantSigningRegistryEntry['publicJwk'];
}

interface RegisterDidRoutesInput {
  app: Hono<AppEnv>;
  didForWellKnownRequest: (requestUrl: string) => string;
  didForTenantPathRequest: (requestUrl: string, tenantSlug: string) => string;
  resolveSigningEntryForDid: (c: AppContext, did: string) => Promise<TenantSigningRegistryEntry | null>;
  didDocumentForSigningEntry: (input: {
    did: string;
    signingEntry: TenantSigningRegistryEntry;
  }) => JsonObject | null;
  jwksDocumentForSigningEntry: (input: {
    signingEntry: TenantSigningRegistryEntry;
    historicalKeys?: readonly SigningKeyLike[];
  }) => JsonObject;
  resolveHistoricalSigningKeysForDid: (c: AppContext, did: string) => readonly SigningKeyLike[];
}

export const registerDidRoutes = (input: RegisterDidRoutesInput): void => {
  const {
    app,
    didForWellKnownRequest,
    didForTenantPathRequest,
    resolveSigningEntryForDid,
    didDocumentForSigningEntry,
    jwksDocumentForSigningEntry,
    resolveHistoricalSigningKeysForDid,
  } = input;

  app.get('/.well-known/did.json', async (c): Promise<Response> => {
    const did = didForWellKnownRequest(c.req.url);
    const signingEntry = await resolveSigningEntryForDid(c, did);

    if (signingEntry === null) {
      return c.json(
        {
          error: 'No DID document configured for request host',
          did,
        },
        404,
      );
    }

    const didDocument = didDocumentForSigningEntry({
      did,
      signingEntry,
    });

    if (didDocument === null) {
      return c.json(
        {
          error: 'DID document generation requires an Ed25519 or P-256 public key',
          did,
        },
        422,
      );
    }

    return c.json(didDocument);
  });

  app.get('/:tenantSlug/did.json', async (c): Promise<Response> => {
    const tenantSlug = c.req.param('tenantSlug');
    const did = didForTenantPathRequest(c.req.url, tenantSlug);
    const signingEntry = await resolveSigningEntryForDid(c, did);

    if (signingEntry === null) {
      return c.json(
        {
          error: 'No DID document configured for tenant path',
          did,
        },
        404,
      );
    }

    const didDocument = didDocumentForSigningEntry({
      did,
      signingEntry,
    });

    if (didDocument === null) {
      return c.json(
        {
          error: 'DID document generation requires an Ed25519 or P-256 public key',
          did,
        },
        422,
      );
    }

    return c.json(didDocument);
  });

  app.get('/.well-known/jwks.json', async (c): Promise<Response> => {
    const did = didForWellKnownRequest(c.req.url);
    const signingEntry = await resolveSigningEntryForDid(c, did);

    if (signingEntry === null) {
      return c.json(
        {
          error: 'No JWKS configured for request host',
          did,
        },
        404,
      );
    }

    return c.json(
      jwksDocumentForSigningEntry({
        signingEntry,
        historicalKeys: resolveHistoricalSigningKeysForDid(c, did),
      }),
    );
  });

  app.get('/:tenantSlug/jwks.json', async (c): Promise<Response> => {
    const tenantSlug = c.req.param('tenantSlug');
    const did = didForTenantPathRequest(c.req.url, tenantSlug);
    const signingEntry = await resolveSigningEntryForDid(c, did);

    if (signingEntry === null) {
      return c.json(
        {
          error: 'No JWKS configured for tenant path',
          did,
        },
        404,
      );
    }

    return c.json(
      jwksDocumentForSigningEntry({
        signingEntry,
        historicalKeys: resolveHistoricalSigningKeysForDid(c, did),
      }),
    );
  });
};
