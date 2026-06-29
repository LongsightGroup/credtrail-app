import type {
  LTI13JwtPayload as LtiLaunchClaims,
  LTISession,
  LTITool,
  LtiLaunchVerificationError as CoreLtiLaunchVerificationError,
} from "@lti-tool/core";
import type { AppBindings } from "../app";
import type { SqlDatabase } from "@credtrail/db";
import {
  normalizeLtiIssuer,
  type LtiIssuerRegistry,
  type LtiIssuerRegistryEntry,
} from "./lti-helpers";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";

type CreateCredTrailLtiTool = typeof createCredTrailLtiTool;

export class LtiLaunchVerificationError extends Error {
  readonly status: 400 | 401 | 501;
  readonly detail: string | undefined;

  constructor(status: 400 | 401 | 501, message: string, detail?: string) {
    super(message);
    this.name = "LtiLaunchVerificationError";
    this.status = status;
    this.detail = detail;
  }
}

const verificationErrorDetail = (error: unknown): string => {
  if (!(error instanceof Error)) {
    return "unknown verification error";
  }

  return error.message
    .replace(/id_token=[^,\s)]+/gi, "id_token=[redacted]")
    .replace(/state=[^,\s)]+/gi, "state=[redacted]")
    .slice(0, 500);
};

const statusForCoreVerificationError = (error: CoreLtiLaunchVerificationError): 400 | 401 => {
  switch (error.code) {
    case "invalid_launch_parameters":
    case "jwt_decode_failed":
    case "missing_issuer":
    case "missing_deployment_id":
      return 400;
    case "launch_config_not_found":
    case "invalid_audience":
    case "invalid_payload":
    case "issuer_mismatch":
    case "jwt_verification_failed":
    case "nonce_mismatch":
    case "nonce_replay":
    case "state_verification_failed":
    case "target_link_uri_mismatch":
    case "unknown_error":
    case "untrusted_audience":
      return 401;
  }
};

const findVerifiedIssuerEntry = (
  registry: LtiIssuerRegistry,
  issuer: string,
  clientId: string,
): { issuer: string; entry: LtiIssuerRegistryEntry } | null => {
  const normalizedIssuer = normalizeLtiIssuer(issuer);

  for (const [candidateIssuer, entry] of Object.entries(registry)) {
    if (normalizeLtiIssuer(candidateIssuer) === normalizedIssuer && entry.clientId === clientId) {
      return {
        issuer: normalizeLtiIssuer(candidateIssuer),
        entry,
      };
    }
  }

  return null;
};

export interface ResolvedLtiLaunch {
  issuer: string;
  issuerEntry: LtiIssuerRegistryEntry;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  ltiTool: LTITool;
}

export const ltiIssuerHasSignedLaunchConfig = (issuerEntry: {
  platformJwksEndpoint?: string;
  tokenEndpoint?: string;
}): boolean => {
  return issuerEntry.platformJwksEndpoint !== undefined && issuerEntry.tokenEndpoint !== undefined;
};

export const resolveLtiLaunch = async (input: {
  idToken: string;
  state: string;
  registry: LtiIssuerRegistry;
  db: SqlDatabase;
  env: AppBindings;
  createLtiTool?: CreateCredTrailLtiTool;
}): Promise<ResolvedLtiLaunch> => {
  const ltiTool = await (input.createLtiTool ?? createCredTrailLtiTool)({
    db: input.db,
    env: input.env,
  });

  const verificationResult = await ltiTool.verifyLaunchDetailed(input.idToken, input.state);

  if (!verificationResult.success) {
    const status = statusForCoreVerificationError(verificationResult.error);
    throw new LtiLaunchVerificationError(
      status,
      "LTI launch verification failed",
      verificationErrorDetail(verificationResult.error),
    );
  }

  const issuerMatch = findVerifiedIssuerEntry(
    input.registry,
    verificationResult.launch.issuer,
    verificationResult.launch.clientId,
  );

  if (issuerMatch === null) {
    throw new LtiLaunchVerificationError(
      400,
      "No issuer registration configured for verified LTI launch",
    );
  }

  if (!ltiIssuerHasSignedLaunchConfig(issuerMatch.entry)) {
    throw new LtiLaunchVerificationError(
      501,
      "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
    );
  }

  const launchClaims = verificationResult.launch.payload;
  const ltiLaunchSession = await ltiTool.createSession(
    verificationResult.launch.payload,
    verificationResult.launch.clientId,
  );

  return {
    issuer: issuerMatch.issuer,
    issuerEntry: issuerMatch.entry,
    launchClaims,
    ltiLaunchSession,
    ltiTool,
  };
};
