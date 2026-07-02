import type {
  LtiAuthorizedLaunch,
  LtiLaunchVerificationResult,
  LtiToolPort,
  LtiVerifyLaunchOptions,
} from "@longsightgroup/lti-tool";
import { ltiLaunchVerificationErrorFromCoreError } from "./launch-verification";

/**
 * Forces LTI launch verification failures through customLaunchRouteHandler.onError.
 *
 * @longsightgroup/lti-tool 0.1.1's verifyLaunchRequest returns its own canned
 * verification-failure response before customLaunchRouteHandler can apply app
 * error policy. Throwing here lets CredTrail map verification failures to its
 * 400/401/501 responses in onError.
 *
 * TODO(lti-tool): delete this adapter when customLaunchRouteHandler exposes a
 * verification-failure hook.
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
