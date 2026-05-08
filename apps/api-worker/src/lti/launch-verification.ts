import type { LTISession, LTITool } from "@lti-tool/core";
import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_TARGET_LINK_URI,
  parseLtiLaunchClaims,
  type LtiLaunchClaims,
} from "@credtrail/lti";
import type { AppBindings } from "../app";
import type { SqlDatabase } from "@credtrail/db";
import { parseCompactJwsHeaderObject, parseCompactJwsPayloadObject } from "../ob3/oauth-utils";
import { asNonEmptyString } from "../utils/value-parsers";
import {
  ltiAudienceIncludesClientId,
  normalizeAbsoluteUrlForComparison,
  normalizeLtiIssuer,
  type LtiIssuerRegistry,
  type LtiIssuerRegistryEntry,
} from "./lti-helpers";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";

export interface LtiLaunchState {
  iss: string;
  clientId: string;
  nonce: string;
  targetLinkUri: string;
  ltiDeploymentId?: string | undefined;
}

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

export interface ResolvedLtiLaunch {
  issuer: string;
  issuerEntry: LtiIssuerRegistryEntry;
  launchClaims: LtiLaunchClaims;
  launchState: LtiLaunchState;
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
  nowIso: string;
}): Promise<ResolvedLtiLaunch> => {
  const idTokenHeader = parseCompactJwsHeaderObject(input.idToken);
  const idTokenPayload = parseCompactJwsPayloadObject(input.idToken);

  if (idTokenHeader === null || idTokenPayload === null) {
    throw new LtiLaunchVerificationError(
      400,
      "id_token must be a compact JWT with valid JSON header and payload",
    );
  }

  const unverifiedIssuer = asNonEmptyString(idTokenPayload.iss);

  if (unverifiedIssuer === null) {
    throw new LtiLaunchVerificationError(400, "id_token is missing issuer");
  }

  const issuer = normalizeLtiIssuer(unverifiedIssuer);
  const issuerEntry = input.registry[issuer];

  if (issuerEntry === undefined) {
    throw new LtiLaunchVerificationError(
      400,
      "No issuer registration configured for id_token issuer",
    );
  }

  const algorithm = asNonEmptyString(idTokenHeader.alg);

  if (algorithm === null || algorithm.toLowerCase() === "none") {
    throw new LtiLaunchVerificationError(
      400,
      'id_token must specify a JOSE alg and must not use "none"',
    );
  }

  if (!ltiIssuerHasSignedLaunchConfig(issuerEntry)) {
    throw new LtiLaunchVerificationError(
      501,
      "LTI issuer requires platform JWKS and token endpoint configuration for signed launches",
    );
  }

  const ltiTool = await createCredTrailLtiTool({
    db: input.db,
    env: input.env,
    defaultTenantId: issuerEntry.tenantId,
  });

  let launchClaims: LtiLaunchClaims;
  let ltiLaunchSession: LTISession;

  try {
    const verifiedPayload = await ltiTool.verifyLaunch(input.idToken, input.state);
    launchClaims = parseLtiLaunchClaims(verifiedPayload);
    const verifiedSession = await ltiTool.createSession(verifiedPayload);
    ltiLaunchSession = {
      ...verifiedSession,
      platform: {
        ...verifiedSession.platform,
        clientId: issuerEntry.clientId,
      },
    };
  } catch (error) {
    throw new LtiLaunchVerificationError(
      401,
      "LTI launch verification failed",
      verificationErrorDetail(error),
    );
  }

  const signedTargetLinkUri = launchClaims[LTI_CLAIM_TARGET_LINK_URI];

  if (signedTargetLinkUri === undefined) {
    throw new LtiLaunchVerificationError(
      400,
      "id_token target_link_uri is required for signed LTI launch",
    );
  }

  const launchState: LtiLaunchState = {
    iss: normalizeLtiIssuer(launchClaims.iss),
    clientId: issuerEntry.clientId,
    nonce: launchClaims.nonce,
    targetLinkUri: signedTargetLinkUri,
    ltiDeploymentId: launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
  };

  if (!ltiAudienceIncludesClientId(launchClaims.aud, launchState.clientId)) {
    throw new LtiLaunchVerificationError(400, "id_token aud does not include configured client_id");
  }

  if (launchClaims.nonce !== launchState.nonce) {
    throw new LtiLaunchVerificationError(400, "id_token nonce does not match launch state nonce");
  }

  const nowEpochSeconds = Math.floor(Date.parse(input.nowIso) / 1000);

  if (launchClaims.exp <= nowEpochSeconds) {
    throw new LtiLaunchVerificationError(400, "id_token is expired");
  }

  if (launchClaims.iat > nowEpochSeconds + 60) {
    throw new LtiLaunchVerificationError(400, "id_token iat is in the future");
  }

  if (
    launchState.ltiDeploymentId !== undefined &&
    launchClaims[LTI_CLAIM_DEPLOYMENT_ID] !== launchState.ltiDeploymentId
  ) {
    throw new LtiLaunchVerificationError(
      400,
      "id_token deployment_id does not match launch initiation",
    );
  }

  const targetLinkUriClaim = launchClaims[LTI_CLAIM_TARGET_LINK_URI];
  const normalizedStateTargetLinkUri = normalizeAbsoluteUrlForComparison(launchState.targetLinkUri);
  const normalizedClaimTargetLinkUri =
    targetLinkUriClaim === undefined ? null : normalizeAbsoluteUrlForComparison(targetLinkUriClaim);

  if (
    targetLinkUriClaim !== undefined &&
    normalizedStateTargetLinkUri !== null &&
    normalizedClaimTargetLinkUri !== normalizedStateTargetLinkUri
  ) {
    throw new LtiLaunchVerificationError(
      400,
      "id_token target_link_uri does not match launch initiation",
    );
  }

  return {
    issuer,
    issuerEntry,
    launchClaims,
    launchState,
    ltiLaunchSession,
    ltiTool,
  };
};
