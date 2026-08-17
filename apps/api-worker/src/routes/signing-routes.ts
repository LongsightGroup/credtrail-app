import {
  createDidDocument,
  generateTenantDidSigningMaterial,
  type DataIntegrityCryptosuite,
  type JsonObject,
} from "@credtrail/core-domain";
import type { Hono } from "hono";
import {
  isValidationParseError,
  parseKeyGenerationRequest,
  parseSignCredentialRequest,
} from "@credtrail/validation";
import type { AppContext, AppEnv } from "../app/types";

type SupportedCredentialProofType = "DataIntegrityProof";

interface SignCredentialForDidInput {
  context: AppContext;
  did: string;
  credential: JsonObject;
  proofType: SupportedCredentialProofType;
  cryptosuite: DataIntegrityCryptosuite;
}

type SignCredentialForDidResult =
  | {
      status: "ok";
      credential: JsonObject;
    }
  | {
      status: "error";
      statusCode: 400 | 404 | 422 | 500 | 502;
      error: string;
      did: string;
    };

interface RegisterSigningRoutesInput {
  app: Hono<AppEnv>;
  signCredentialForDid: (input: SignCredentialForDidInput) => Promise<SignCredentialForDidResult>;
}

export const registerSigningRoutes = (input: RegisterSigningRoutesInput): void => {
  const { app, signCredentialForDid } = input;

  app.post("/v1/signing/keys/generate", async (c) => {
    const payload = await c.req.json<unknown>();
    const request = parseKeyGenerationRequest(payload);
    const signingMaterial =
      request.keyId === undefined
        ? await generateTenantDidSigningMaterial({
            did: request.did,
          })
        : await generateTenantDidSigningMaterial({
            did: request.did,
            keyId: request.keyId,
          });
    const didDocument = createDidDocument({
      did: signingMaterial.did,
      keyId: signingMaterial.keyId,
      publicJwk: signingMaterial.publicJwk,
    });

    return c.json(
      {
        didDocument,
        keyMaterial: signingMaterial,
      },
      201,
    );
  });

  app.post("/v1/signing/credentials", async (c) => {
    const payload = await c.req.json<unknown>();
    let request: ReturnType<typeof parseSignCredentialRequest>;

    try {
      request = parseSignCredentialRequest(payload);
    } catch (error) {
      if (isValidationParseError(error)) {
        return c.json(
          {
            error: "Invalid credential signing request payload",
          },
          400,
        );
      }

      throw error;
    }

    const signingResult = await signCredentialForDid({
      context: c,
      did: request.did,
      credential: request.credential,
      proofType: request.proofType ?? "DataIntegrityProof",
      cryptosuite: request.cryptosuite ?? "eddsa-rdfc-2022",
    });

    if (signingResult.status !== "ok") {
      return c.json(
        {
          error: signingResult.error,
          did: request.did,
        },
        signingResult.statusCode,
      );
    }

    return c.json(
      {
        did: request.did,
        credential: signingResult.credential,
      },
      201,
    );
  });
};
