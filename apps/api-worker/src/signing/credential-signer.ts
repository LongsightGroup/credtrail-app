import {
  signCredentialWithDataIntegrityProof,
  type DataIntegrityCryptosuite,
  type JsonObject,
} from "@credtrail/core-domain";
import type { TenantSigningRegistryEntry } from "@credtrail/validation";
import { withCredTrailUserAgent } from "../http/outbound-user-agent";
import { isEd25519SigningPrivateJwk, toEd25519PrivateJwk } from "./key-material";
import type { RemoteSignerRegistryEntry } from "./registry";

export type SupportedCredentialProofType = "DataIntegrityProof";

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
      status: "ok";
      keyId: string;
      verificationMethod: string;
      credential: JsonObject;
    }
  | {
      status: "error";
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
      status: "ok";
      credential: JsonObject;
    }
  | {
      status: "error";
      reason: string;
    }
> => {
  const abortController = new AbortController();
  const timeoutHandle: ReturnType<typeof setTimeout> = setTimeout(() => {
    abortController.abort("remote-signer-timeout");
  }, input.remoteSigner.timeoutMs);

  let response: Response;

  try {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };

    if (input.remoteSigner.authorizationHeader !== null) {
      headers.authorization = input.remoteSigner.authorizationHeader;
    }

    response = await fetch(input.remoteSigner.url, {
      method: "POST",
      headers: withCredTrailUserAgent(headers),
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
      status: "error",
      reason: "request to remote signer failed",
    };
  } finally {
    clearTimeout(timeoutHandle);
  }

  if (!response.ok) {
    return {
      status: "error",
      reason: `remote signer returned HTTP ${String(response.status)}`,
    };
  }

  const responseBody = await response.json<unknown>().catch(() => null);
  const responseObject = input.asJsonObject(responseBody);
  const signedCredential = input.asJsonObject(responseObject?.credential);

  if (signedCredential === null) {
    return {
      status: "error",
      reason: "remote signer response is missing a JSON credential object",
    };
  }

  const signedProof = input.selectCredentialProofObject(signedCredential);

  if (signedProof === null) {
    return {
      status: "error",
      reason: "remote signer credential is missing a proof object",
    };
  }

  const signedProofType = input.asNonEmptyString(signedProof.type);
  const signedVerificationMethod = input.asNonEmptyString(signedProof.verificationMethod);

  if (
    signedProofType !== input.proofType ||
    signedVerificationMethod !== input.verificationMethod
  ) {
    return {
      status: "error",
      reason: "remote signer proof metadata does not match requested proof parameters",
    };
  }

  const signedCryptosuite = input.asNonEmptyString(signedProof.cryptosuite);

  if (signedCryptosuite !== input.cryptosuite) {
    return {
      status: "error",
      reason: "remote signer proof cryptosuite does not match requested cryptosuite",
    };
  }

  return {
    status: "ok",
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
        status: "error",
        statusCode: 404,
        error: "No signing configuration for requested DID",
        did: request.did,
      };
    }

    const verificationMethod = `${request.did}#${signingEntry.keyId}`;

    const cryptosuite = request.cryptosuite ?? "eddsa-rdfc-2022";

    if (signingEntry.privateJwk !== undefined) {
      if (!isEd25519SigningPrivateJwk(signingEntry.privateJwk)) {
        return {
          status: "error",
          statusCode: 422,
          error:
            request.ed25519KeyRequirementError ??
            "DataIntegrity eddsa-rdfc-2022 signing requires an Ed25519 private key",
          did: request.did,
        };
      }

      const signedCredential = await signCredentialWithDataIntegrityProof({
        credential: request.credential,
        privateJwk: toEd25519PrivateJwk(signingEntry.privateJwk),
        verificationMethod,
        cryptosuite,
        ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
      });

      return {
        status: "ok",
        keyId: signingEntry.keyId,
        verificationMethod,
        credential: signedCredential,
      };
    }

    const remoteSigner = input.resolveRemoteSignerRegistryEntryForDid(request.context, request.did);

    if (remoteSigner === null) {
      return {
        status: "error",
        statusCode: 500,
        error:
          request.missingPrivateKeyError ??
          "DID is missing private signing key material and no remote signer is configured",
        did: request.did,
      };
    }

    const remoteSignerResult = await signCredentialWithRemoteSigner({
      did: request.did,
      keyId: signingEntry.keyId,
      verificationMethod,
      credential: request.credential,
      proofType: request.proofType,
      cryptosuite,
      ...(request.createdAt === undefined ? {} : { createdAt: request.createdAt }),
      remoteSigner,
      asJsonObject: input.asJsonObject,
      asNonEmptyString: input.asNonEmptyString,
      selectCredentialProofObject: input.selectCredentialProofObject,
    });

    if (remoteSignerResult.status !== "ok") {
      return {
        status: "error",
        statusCode: 502,
        error: `Remote signer request failed: ${remoteSignerResult.reason}`,
        did: request.did,
      };
    }

    return {
      status: "ok",
      keyId: signingEntry.keyId,
      verificationMethod,
      credential: remoteSignerResult.credential,
    };
  };
};
