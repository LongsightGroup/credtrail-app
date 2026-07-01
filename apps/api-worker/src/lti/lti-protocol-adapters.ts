import type {
  LtiAuthorizedLaunch,
  LtiLaunchVerificationResult,
  LtiToolPort,
  LtiVerifyLaunchOptions,
} from "@longsightgroup/lti-tool";
import { ltiLaunchVerificationErrorFromCoreError } from "./launch-verification";

/**
 * Adapts a result-based LTI tool to the throw-on-failure contract used by package Hono handlers.
 */
export const createVerificationThrowingLtiTool = (ltiTool: LtiToolPort): LtiToolPort => {
  async function verifyLaunchOrThrow(
    idToken: string,
    state: string,
  ): Promise<LtiLaunchVerificationResult>;
  async function verifyLaunchOrThrow<TAuthorization>(
    idToken: string,
    state: string,
    options: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>>;
  async function verifyLaunchOrThrow<TAuthorization>(
    idToken: string,
    state: string,
    options?: LtiVerifyLaunchOptions<TAuthorization>,
  ): Promise<
    LtiLaunchVerificationResult | LtiLaunchVerificationResult<LtiAuthorizedLaunch<TAuthorization>>
  > {
    const verificationResult =
      options === undefined
        ? await ltiTool.verifyLaunch(idToken, state)
        : await ltiTool.verifyLaunch(idToken, state, options);

    if (!verificationResult.success) {
      throw ltiLaunchVerificationErrorFromCoreError(verificationResult.error);
    }

    return verificationResult;
  }

  return {
    getJWKS: () => ltiTool.getJWKS(),
    handleLogin: (params) => ltiTool.handleLogin(params),
    verifyLaunch: verifyLaunchOrThrow,
    createSessionFromVerifiedLaunch: (launch) => ltiTool.createSessionFromVerifiedLaunch(launch),
    getSession: (sessionId) => ltiTool.getSession(sessionId),
    createAdvantage: (session) => ltiTool.createAdvantage(session),
  };
};
