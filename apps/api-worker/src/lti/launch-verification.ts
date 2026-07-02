import type {
  LtiLaunchVerificationError as CoreLtiLaunchVerificationError,
  LTI13JwtPayload as LtiLaunchClaims,
  LTISession,
  LtiToolPort,
  LtiVerifiedLaunch,
} from "@longsightgroup/lti-tool";
import {
  findLtiIssuerRegistryEntry,
  type LtiIssuerRegistry,
  type LtiIssuerRegistryEntry,
} from "./lti-issuer-registry";
import { ltiErrorDetail } from "./redaction";

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

const statusForCoreVerificationError = (error: CoreLtiLaunchVerificationError): 400 | 401 => {
  switch (error.code) {
    case "invalid_launch_parameters":
    case "jwt_decode_failed":
    case "missing_issuer":
    case "missing_deployment_id":
    case "verified_launch_authorization_failed":
      return 400;
    case "launch_config_missing_jwks_endpoint":
    case "launch_config_missing_token_endpoint":
    case "launch_client_not_found":
    case "launch_config_invalid":
    case "launch_config_lookup_failed":
    case "launch_config_not_found":
    case "launch_deployment_not_found":
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

const statusForLaunchVerificationError = (
  error: CoreLtiLaunchVerificationError,
): 400 | 401 | 501 => {
  switch (error.code) {
    case "launch_config_missing_jwks_endpoint":
    case "launch_config_missing_token_endpoint":
      return 501;
    default:
      return statusForCoreVerificationError(error);
  }
};

const messageForLaunchVerificationError = (error: CoreLtiLaunchVerificationError): string => {
  switch (error.code) {
    case "launch_config_missing_jwks_endpoint":
    case "launch_config_missing_token_endpoint":
      return "LTI issuer requires platform JWKS and token endpoint configuration for signed launches";
    case "verified_launch_authorization_failed":
      return error.message;
    default:
      return "LTI launch verification failed";
  }
};

export const ltiLaunchVerificationErrorFromCoreError = (
  error: CoreLtiLaunchVerificationError,
): LtiLaunchVerificationError => {
  return new LtiLaunchVerificationError(
    statusForLaunchVerificationError(error),
    messageForLaunchVerificationError(error),
    ltiErrorDetail(error),
  );
};

/**
 * CredTrail tenant authorization attached to an otherwise verified LTI launch.
 */
export type LtiLaunchAuthorization = {
  readonly issuer: string;
  readonly entry: LtiIssuerRegistryEntry;
};

/**
 * Authorizes a cryptographically verified LTI launch against CredTrail's issuer registry.
 */
export const authorizeVerifiedLaunchForRegistry = (
  registry: LtiIssuerRegistry,
  launch: LtiVerifiedLaunch,
):
  | { success: true; data: LtiLaunchAuthorization }
  | { success: false; code: string; message: string } => {
  const issuerMatch = findLtiIssuerRegistryEntry(registry, launch.issuer, launch.clientId);

  if (issuerMatch === null) {
    return {
      success: false,
      code: "issuer_registration_not_configured",
      message: "No issuer registration configured for verified LTI launch",
    };
  }

  return {
    success: true,
    data: issuerMatch,
  };
};

export interface ResolvedLtiLaunch {
  issuer: string;
  issuerEntry: LtiIssuerRegistryEntry;
  launchClaims: LtiLaunchClaims;
  ltiLaunchSession: LTISession;
  ltiTool: LtiToolPort;
}

export const ltiIssuerHasSignedLaunchConfig = (issuerEntry: {
  platformJwksEndpoint?: string;
  tokenEndpoint?: string;
}): boolean => {
  return issuerEntry.platformJwksEndpoint !== undefined && issuerEntry.tokenEndpoint !== undefined;
};
