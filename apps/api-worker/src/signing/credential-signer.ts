import {
  signCredentialWithDataIntegrityProof,
  signCredentialWithEd25519Signature2020,
  type DataIntegrityCryptosuite,
  type JsonObject,
} from '@credtrail/core-domain';
import type { TenantSigningRegistryEntry } from '@credtrail/validation';
import {
  isEd25519SigningPrivateJwk,
  isP256SigningPrivateJwk,
  toEd25519PrivateJwk,
  toP256PrivateJwk,
} from './key-material';
import type { RemoteSignerRegistryEntry } from './registry';

export type SupportedCredentialProofType = 'Ed25519Signature2020' | 'DataIntegrityProof';

export interface SignCredentialForDidInput<ContextType> {
  context: ContextType;
  did: string;
  credential: JsonObject;
  proofType: SupportedCredentialProofType;
  cryptosuite?: DataIntegrityCryptosuite;
  createdAt?: string;
  missingPrivateKeyError?: string;
  ed25519KeyRequirementError?: string;
}

export type SignCredentialErrorStatusCode = 400 | 404 | 422 | 500 | 502;

export type SignCredentialForDidResult =
  | {
      status: 'ok';
      keyId: string;
      verificationMethod: string;
      credential: JsonObject;
    }
  | {
      status: 'error';
      statusCode: SignCredentialErrorStatusCode;
      error: string;
      did: string;
    };

interface CreateCredentialSignerInput<ContextType> {
  resolveSigningEntryForDid: (
    context: ContextType,
    did: string,
  ) => Promise<TenantSigningRegistryEntry | null>;
  resolveRemoteSignerRegistryEntryForDid: (
    context: ContextType,
    did: string,
  ) => RemoteSignerRegistryEntry | null;
  asJsonObject: (value: unknown) => JsonObject | null;
  asNonEmptyString: (value: unknown) => string | null;
  selectCredentialProofObject: (credential: JsonObject) => JsonObject | null;
}

const signCredentialWithRemoteSigner = async (input: {
  did: string;
  keyId: string;
  verificationMethod: string;
  credential: JsonObject;
  proofType: SupportedCredentialProofType;
  cryptosuite?: DataIntegrityCryptosuite;
  createdAt?: string;
  remoteSigner: RemoteSignerRegistryEntry;
  asJsonObject: (value: unknown) => JsonObject | null;
  asNonEmptyString: (value: unknown) => string | null;
  selectCredentialProofObject: (credential: JsonObject) => JsonObject | null;
}): Promise<
  | {
      status: 'ok';
      credential: JsonObject;
    }
  | {
      status: 'error';
      reason: string;
    }
> => {
  const abortController = new AbortController();
  const timeoutHandle: ReturnType<typeof setTimeout> = setTimeout(() => {
    abortController.abort('remote-signer-timeout');
  }, input.remoteSigner.timeoutMs);

  let response: Response;

  try {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      accept: 'application/json',
    };

    if (input.remoteSigner.authorizationHeader !== null) {
      headers.authorization = input.remoteSigner.authorizationHeader;
    }

    response = await fetch(input.remoteSigner.url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        did: input.did,
        keyId: input.keyId,
        verificationMethod: input.verificationMethod,
        proofType: input.proofType,
        ...(input.cryptosuite === undefined ? {} : { cryptosuite: input.cryptosuite }),
        ...(input.createdAt === undefined ? {} : { createdAt: input.createdAt }),
        credential: input.credential,
      }),
      signal: abortController.signal,
    });
  } catch {
    return {
      status: 'error',
      reason: 'request to remote signer failed',
    };
  } finally {
    clearTimeout(timeoutHandle);
  }

  if (!response.ok) {
    return {
      status: 'error',
      reason: `remote signer returned HTTP ${String(response.status)}`,
    };
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  const responseObject = input.asJsonObject(responseBody);
  const signedCredential = input.asJsonObject(responseObject?.credential);

  if (signedCredential === null) {
    return {
      status: 'error',
      reason: 'remote signer response is missing a JSON credential object',
    };
  }

  const signedProof = input.selectCredentialProofObject(signedCredential);

  if (signedProof === null) {
    return {
      status: 'error',
      reason: 'remote signer credential is missing a proof object',
    };
  }

  const signedProofType = input.asNonEmptyString(signedProof.type);
  const signedVerificationMethod = input.asNonEmptyString(signedProof.verificationMethod);

  if (
    signedProofType !== input.proofType ||
    signedVerificationMethod !== input.verificationMethod
  ) {
    return {
      status: 'error',
      reason: 'remote signer proof metadata does not match requested proof parameters',
    };
  }

  if (input.proofType === 'DataIntegrityProof' && input.cryptosuite !== undefined) {
    const signedCryptosuite = input.asNonEmptyString(signedProof.cryptosuite);

    if (signedCryptosuite !== input.cryptosuite) {
      return {
        status: 'error',
        reason: 'remote signer proof cryptosuite does not match requested cryptosuite',
      };
    }
  }

  return {
    status: 'ok',
    credential: signedCredential,
  };
};

export const createSignCredentialForDid = <ContextType>(
  input: CreateCredentialSignerInput<ContextType>,
) => {
  return async (
    request: SignCredentialForDidInput<ContextType>,
  ): Promise<SignCredentialForDidResult> => {
    const signingEntry = await input.resolveSigningEntryForDid(request.context, request.did);

    if (signingEntry === null) {
      return {
        status: 'error',
        statusCode: 404,
        error: 'No signing configuration for requested DID',
        did: request.did,
      };
    }

    const verificationMethod = `${request.did}#${signingEntry.keyId}`;

    if (request.proofType === 'DataIntegrityProof' && request.cryptosuite === undefined) {
      return {
        status: 'error',
        statusCode: 400,
        error: 'DataIntegrityProof signing requires a cryptosuite value',
        did: request.did,
      };
    }

    if (signingEntry.privateJwk !== undefined) {
      let signedCredential: JsonObject;

      if (request.proofType === 'DataIntegrityProof') {
        const cryptosuite = request.cryptosuite;

        if (cryptosuite === undefined) {
          return {
            status: 'error',
            statusCode: 400,
            error: 'DataIntegrityProof signing requires a cryptosuite value',
            did: request.did,
          };
        }

        if (cryptosuite === 'eddsa-rdfc-2022') {
          if (!isEd25519SigningPrivateJwk(signingEntry.privateJwk)) {
            return {
              status: 'error',
              statusCode: 422,
              error: 'DataIntegrity eddsa-rdfc-2022 signing requires an Ed25519 private key',
              did: request.did,
            };
          }

          signedCredential = await signCredentialWithDataIntegrityProof({
            credential: request.credential,
            privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
            verificationMethod,
            cryptosuite,
            ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
          });
        } else {
          if (!isP256SigningPrivateJwk(signingEntry.privateJwk)) {
            return {
              status: 'error',
              statusCode: 422,
              error: 'DataIntegrity ecdsa-sd-2023 signing requires a P-256 private key',
              did: request.did,
            };
          }

          signedCredential = await signCredentialWithDataIntegrityProof({
            credential: request.credential,
            privateJwk: toP256PrivateJwk(signingEntry.privateJwk),
            verificationMethod,
            cryptosuite,
            ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
          });
        }
      } else {
        if (!isEd25519SigningPrivateJwk(signingEntry.privateJwk)) {
          return {
            status: 'error',
            statusCode: 422,
            error:
              request.ed25519KeyRequirementError ??
              'Credential signing endpoint requires an Ed25519 private key',
            did: request.did,
          };
        }

        signedCredential = await signCredentialWithEd25519Signature2020({
          credential: request.credential,
          privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
          verificationMethod,
          ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
        });
      }

      return {
        status: 'ok',
        keyId: signingEntry.keyId,
        verificationMethod,
        credential: signedCredential,
      };
    }

    const remoteSigner = input.resolveRemoteSignerRegistryEntryForDid(request.context, request.did);

    if (remoteSigner === null) {
      return {
        status: 'error',
        statusCode: 500,
        error:
          request.missingPrivateKeyError ??
          'DID is missing private signing key material and no remote signer is configured',
        did: request.did,
      };
    }

    const remoteSignerResult = await signCredentialWithRemoteSigner({
      did: request.did,
      keyId: signingEntry.keyId,
      verificationMethod,
      credential: request.credential,
      proofType: request.proofType,
      ...(request.cryptosuite === undefined ? {} : { cryptosuite: request.cryptosuite }),
      ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
      remoteSigner,
      asJsonObject: input.asJsonObject,
      asNonEmptyString: input.asNonEmptyString,
      selectCredentialProofObject: input.selectCredentialProofObject,
    });

    if (remoteSignerResult.status !== 'ok') {
      return {
        status: 'error',
        statusCode: 502,
        error: `Remote signer request failed: ${remoteSignerResult.reason}`,
        did: request.did,
      };
    }

    return {
      status: 'ok',
      keyId: signingEntry.keyId,
      verificationMethod,
      credential: remoteSignerResult.credential,
    };
  };
};
