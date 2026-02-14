import type {
  Ed25519PrivateJwk,
  Ed25519PublicJwk,
  P256PrivateJwk,
  P256PublicJwk,
} from '@credtrail/core-domain';
import type { TenantSigningRegistryEntry } from '@credtrail/validation';

export type Ed25519SigningPublicJwk = Extract<
  TenantSigningRegistryEntry['publicJwk'],
  { kty: 'OKP'; crv: 'Ed25519' }
>;
export type P256SigningPublicJwk = Extract<
  TenantSigningRegistryEntry['publicJwk'],
  { kty: 'EC'; crv: 'P-256' }
>;
export type Ed25519SigningPrivateJwk = NonNullable<
  Extract<TenantSigningRegistryEntry['privateJwk'], { kty: 'OKP'; crv: 'Ed25519' }>
>;
export type P256SigningPrivateJwk = NonNullable<
  Extract<TenantSigningRegistryEntry['privateJwk'], { kty: 'EC'; crv: 'P-256' }>
>;
export type SigningPublicJwk = TenantSigningRegistryEntry['publicJwk'];

export const isEd25519SigningPublicJwk = (
  jwk: TenantSigningRegistryEntry['publicJwk'],
): jwk is Ed25519SigningPublicJwk => {
  return jwk.kty === 'OKP';
};

export const isP256SigningPublicJwk = (
  jwk: TenantSigningRegistryEntry['publicJwk'],
): jwk is P256SigningPublicJwk => {
  return jwk.kty === 'EC';
};

export const isEd25519SigningPrivateJwk = (
  jwk: TenantSigningRegistryEntry['privateJwk'],
): jwk is Ed25519SigningPrivateJwk => {
  return jwk?.kty === 'OKP';
};

export const isP256SigningPrivateJwk = (
  jwk: TenantSigningRegistryEntry['privateJwk'],
): jwk is P256SigningPrivateJwk => {
  return jwk?.kty === 'EC';
};

export const toEd25519PublicJwk = (jwk: Ed25519SigningPublicJwk): Ed25519PublicJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    kid: jwk.kid,
  };
};

export const toP256PublicJwk = (jwk: P256SigningPublicJwk): P256PublicJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    kid: jwk.kid,
  };
};

export const toEd25519PrivateJwk = (jwk: Ed25519SigningPrivateJwk): Ed25519PrivateJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      d: jwk.d,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    d: jwk.d,
    kid: jwk.kid,
  };
};

export const toP256PrivateJwk = (jwk: P256SigningPrivateJwk): P256PrivateJwk => {
  if (jwk.kid === undefined) {
    return {
      kty: jwk.kty,
      crv: jwk.crv,
      x: jwk.x,
      y: jwk.y,
      d: jwk.d,
    };
  }

  return {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y,
    d: jwk.d,
    kid: jwk.kid,
  };
};
