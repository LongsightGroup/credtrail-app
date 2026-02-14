import { createDidDocument, createDidWeb, type JsonObject } from '@credtrail/core-domain';
import type { TenantSigningRegistryEntry } from '@credtrail/validation';
import type { HistoricalSigningKeyEntry } from './registry';
import {
  isEd25519SigningPublicJwk,
  isP256SigningPublicJwk,
  toEd25519PublicJwk,
  toP256PublicJwk,
  type SigningPublicJwk,
} from './key-material';

export const didForWellKnownRequest = (requestUrl: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host });
};

export const didForTenantPathRequest = (requestUrl: string, tenantSlug: string): string => {
  const request = new URL(requestUrl);
  return createDidWeb({ host: request.host, pathSegments: [tenantSlug] });
};

export const didDocumentForSigningEntry = (input: {
  did: string;
  signingEntry: TenantSigningRegistryEntry;
}): JsonObject | null => {
  const verificationMethodId = `${input.did}#${input.signingEntry.keyId}`;

  if (isEd25519SigningPublicJwk(input.signingEntry.publicJwk)) {
    return createDidDocument({
      did: input.did,
      keyId: input.signingEntry.keyId,
      publicJwk: toEd25519PublicJwk(input.signingEntry.publicJwk),
    }) as unknown as JsonObject;
  }

  if (isP256SigningPublicJwk(input.signingEntry.publicJwk)) {
    const didDocument: JsonObject = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
      id: input.did,
      verificationMethod: [
        {
          id: verificationMethodId,
          type: 'JsonWebKey2020',
          controller: input.did,
          publicKeyJwk: toP256PublicJwk(input.signingEntry.publicJwk) as unknown as JsonObject,
        },
      ],
      assertionMethod: [verificationMethodId],
    };

    return didDocument;
  }

  return null;
};

const publicJwkFromSigningPublicJwk = (publicJwk: SigningPublicJwk): JsonObject => {
  if (isEd25519SigningPublicJwk(publicJwk)) {
    return toEd25519PublicJwk(publicJwk) as unknown as JsonObject;
  }

  if (isP256SigningPublicJwk(publicJwk)) {
    return toP256PublicJwk(publicJwk) as unknown as JsonObject;
  }

  return publicJwk as unknown as JsonObject;
};

export const jwksDocumentForSigningEntry = (input: {
  signingEntry: TenantSigningRegistryEntry;
  historicalKeys?: readonly HistoricalSigningKeyEntry[];
}): JsonObject => {
  const keys: JsonObject[] = [publicJwkFromSigningPublicJwk(input.signingEntry.publicJwk)];
  const activeKeyId = input.signingEntry.keyId;

  for (const historicalEntry of input.historicalKeys ?? []) {
    if (historicalEntry.keyId === activeKeyId) {
      continue;
    }

    keys.push(publicJwkFromSigningPublicJwk(historicalEntry.publicJwk));
  }

  return {
    keys,
  };
};
