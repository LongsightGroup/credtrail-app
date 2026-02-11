import { describe, expect, it } from 'vitest';

import {
  type JsonObject,
  createDidDocument,
  createDidWeb,
  decodeJwkPublicKeyMultibase,
  didWebDocumentPath,
  encodeJwkPublicKeyMultibase,
  generateTenantDidSigningMaterial,
  signCredentialWithDataIntegrityProof,
  signCredentialWithEd25519Signature2020,
  verifyCredentialProofWithDataIntegrity,
  verifyCredentialProofWithEd25519Signature2020,
} from './index';

describe('did:web helpers', () => {
  it('builds did:web identifiers for host and tenant path', () => {
    expect(createDidWeb({ host: 'issuers.credtrail.org' })).toBe('did:web:issuers.credtrail.org');
    expect(createDidWeb({ host: 'issuers.credtrail.org', pathSegments: ['tenant-a'] })).toBe(
      'did:web:issuers.credtrail.org:tenant-a',
    );
  });

  it('maps did:web identifiers to document path', () => {
    expect(didWebDocumentPath('did:web:issuers.credtrail.org')).toBe('/.well-known/did.json');
    expect(didWebDocumentPath('did:web:issuers.credtrail.org:tenant-a')).toBe('/tenant-a/did.json');
  });
});

describe('credential signing', () => {
  const sampleCredential = (did: string, id: string): JsonObject => {
    return {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id,
      type: ['VerifiableCredential', 'OpenBadgeCredential'],
      issuer: did,
      credentialSubject: {
        id: 'mailto:learner@example.edu',
        achievement: {
          id: 'urn:uuid:badge-123',
          type: ['Achievement'],
          name: 'TypeScript Fundamentals',
        },
      },
    };
  };

  const requireJwkString = (value: unknown, field: string): string => {
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error(`Expected non-empty string for JWK field "${field}"`);
    }

    return value;
  };

  it('generates keys, signs credentials, and verifies proof', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-a'],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
      keyId: 'key-1',
    });
    const didDocument = createDidDocument({
      did,
      keyId: signingMaterial.keyId,
      publicJwk: signingMaterial.publicJwk,
    });
    const signedCredential = await signCredentialWithEd25519Signature2020({
      credential: sampleCredential(did, 'urn:uuid:vc-123'),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
    });

    expect(didDocument.id).toBe(did);
    expect(didDocument.verificationMethod[0].type).toBe('Multikey');
    expect(didDocument.verificationMethod[0].publicKeyMultibase).toContain('z');
    expect(signedCredential.proof.type).toBe('Ed25519Signature2020');
    expect(signedCredential.proof.verificationMethod).toBe(`${did}#${signingMaterial.keyId}`);
    const encodedMultibase = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
    expect(didDocument.verificationMethod[0].publicKeyMultibase).toBe(encodedMultibase);
    expect(decodeJwkPublicKeyMultibase(encodedMultibase)).toBe(signingMaterial.publicJwk.x);

    const isValid = await verifyCredentialProofWithEd25519Signature2020({
      credential: signedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it('fails verification when credential payload is modified', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-b'],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithEd25519Signature2020({
      credential: sampleCredential(did, 'urn:uuid:vc-456'),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
    });

    const tamperedCredential = {
      ...signedCredential,
      issuer: 'did:web:tampered.credtrail.org:tenant-b',
    };

    const isValid = await verifyCredentialProofWithEd25519Signature2020({
      credential: tamperedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(false);
  });

  it('rejects multibase values that do not include the Ed25519 multicodec prefix', () => {
    expect(() => decodeJwkPublicKeyMultibase('z3vQB7B6MrGQZaxCuFg4oh')).toThrow(
      'Expected multicodec value with Ed25519 0xed01 prefix',
    );
  });

  it('uses multibase-derived key IDs by default for generated signing material', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-c'],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const expectedKeyId = encodeJwkPublicKeyMultibase(signingMaterial.publicJwk);
    const didDocument = createDidDocument({
      did,
      keyId: signingMaterial.keyId,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(signingMaterial.keyId).toBe(expectedKeyId);
    expect(signingMaterial.publicJwk.kid).toBe(expectedKeyId);
    expect(signingMaterial.privateJwk.kid).toBe(expectedKeyId);
    expect(didDocument.verificationMethod[0].id).toBe(`${did}#${expectedKeyId}`);
  });

  it('signs and verifies DataIntegrityProof with eddsa-rdfc-2022', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-d'],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, 'urn:uuid:vc-789'),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
      cryptosuite: 'eddsa-rdfc-2022',
    });

    expect(signedCredential.proof.type).toBe('DataIntegrityProof');
    expect(signedCredential.proof.cryptosuite).toBe('eddsa-rdfc-2022');

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: signingMaterial.publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it('signs and verifies DataIntegrityProof with ecdsa-sd-2023', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-e'],
    });
    const generated = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const exportedPublicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey);
    const exportedPrivateJwk = await crypto.subtle.exportKey('jwk', generated.privateKey);
    const publicJwk: {
      kty: 'EC';
      crv: 'P-256';
      x: string;
      y: string;
      kid: string;
    } = {
      kty: 'EC',
      crv: 'P-256',
      x: requireJwkString(exportedPublicJwk.x, 'x'),
      y: requireJwkString(exportedPublicJwk.y, 'y'),
      kid: 'key-p256',
    };
    const privateJwk = {
      ...publicJwk,
      d: requireJwkString(exportedPrivateJwk.d, 'd'),
    };
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, 'urn:uuid:vc-790'),
      privateJwk,
      verificationMethod: `${did}#${publicJwk.kid}`,
      cryptosuite: 'ecdsa-sd-2023',
    });

    expect(signedCredential.proof.type).toBe('DataIntegrityProof');
    expect(signedCredential.proof.cryptosuite).toBe('ecdsa-sd-2023');

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk,
    });

    expect(isValid).toBe(true);
  });

  it('fails DataIntegrityProof verification with mismatched key type', async () => {
    const did = createDidWeb({
      host: 'issuers.credtrail.org',
      pathSegments: ['tenant-f'],
    });
    const signingMaterial = await generateTenantDidSigningMaterial({
      did,
    });
    const signedCredential = await signCredentialWithDataIntegrityProof({
      credential: sampleCredential(did, 'urn:uuid:vc-791'),
      privateJwk: signingMaterial.privateJwk,
      verificationMethod: `${did}#${signingMaterial.keyId}`,
      cryptosuite: 'eddsa-rdfc-2022',
    });
    const generated = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const exportedPublicJwk = await crypto.subtle.exportKey('jwk', generated.publicKey);
    const wrongPublicJwk: {
      kty: 'EC';
      crv: 'P-256';
      x: string;
      y: string;
      kid: string;
    } = {
      kty: 'EC',
      crv: 'P-256',
      x: requireJwkString(exportedPublicJwk.x, 'x'),
      y: requireJwkString(exportedPublicJwk.y, 'y'),
      kid: 'wrong-key',
    };

    const isValid = await verifyCredentialProofWithDataIntegrity({
      credential: signedCredential,
      publicJwk: wrongPublicJwk,
    });

    expect(isValid).toBe(false);
  });
});
