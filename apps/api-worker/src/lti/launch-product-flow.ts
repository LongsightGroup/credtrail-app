import { attachLtiLaunchSessionPrincipal } from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app/types";
import { renderAppPage } from "../ui/render-page";
import {
  linkInstructorLmsIdentity,
  type InstructorLmsIdentityLinkFailure,
} from "./instructor-lms-identity";
import { renderLtiDeepLinkingLaunchResponse } from "./launch-deep-linking-flow";
import { linkLtiLaunchAccount, type LinkedLtiLaunchAccount } from "./launch-account-linking";
import type { ResolvedLtiLaunchMessage } from "./launch-message";
import {
  type EstablishedLtiLaunchSession,
  type HandleVerifiedLtiLaunch,
  type HandleVerifiedLtiLaunchInput,
  type ProductFlowFailure,
  type ProductFlowResult,
  type ValidatedLtiLaunchMessage,
  productFlowFailure,
  productFlowSuccess,
} from "./launch-product-types";
import {
  prepareLaunchedResourceLinkPlacement,
  renderLtiResourceLinkLaunchResponse,
} from "./launch-resource-link-flow";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { ltiLogger } from "./log";
import { ltiEmailFromClaims, ltiSourcedIdFromClaims } from "./lti-helpers";
import { ltiErrorDetail } from "./redaction";
import { ltiRuleUnavailablePage } from "./pages";

export type { HandleVerifiedLtiLaunch, HandleVerifiedLtiLaunchInput };

const isValidatedDeepLinkingLaunch = (
  launch: ValidatedLtiLaunchMessage,
): launch is Extract<ValidatedLtiLaunchMessage, { launchMessage: { kind: "deep-linking" } }> => {
  return launch.launchMessage.kind === "deep-linking";
};

export const responseFromProductFailure = (
  c: AppContext,
  failure: ProductFlowFailure,
): Response | Promise<Response> => {
  if (failure.surface === "lti_rule_unavailable") {
    return renderAppPage(c, ltiRuleUnavailablePage({ message: failure.body.error }), 403);
  }

  return c.json(failure.body, failure.status);
};

const validateResolvedLtiLaunchMessage = (input: {
  launchMessage: ResolvedLtiLaunchMessage;
}): ProductFlowResult<ValidatedLtiLaunchMessage> => {
  if (input.launchMessage.kind === "deep-linking") {
    return productFlowSuccess({
      launchMessage: input.launchMessage,
    });
  }

  return productFlowSuccess({
    kind: "unresolved",
    launchMessage: input.launchMessage,
  });
};

const accountLinkingFailure = (c: AppContext, error: unknown): ProductFlowFailure => {
  const detail = ltiErrorDetail(error);

  if (c.env.APP_ENV === "production") {
    return {
      status: 500,
      body: {
        error: "Unable to link LTI launch to local account",
      },
    };
  }

  return {
    status: 500,
    body: {
      error: "Unable to link LTI launch to local account",
      ...(detail === undefined ? {} : { detail }),
    },
  };
};

const instructorLmsIdentityFailure = (
  c: AppContext,
  error: InstructorLmsIdentityLinkFailure,
): ProductFlowFailure => {
  if (c.env.APP_ENV === "production") {
    return {
      status: 500,
      body: {
        error: error.message,
      },
    };
  }

  const detail = ltiErrorDetail(error.cause);

  return {
    status: 500,
    body: {
      error: error.message,
      ...(detail === undefined ? {} : { detail }),
    },
  };
};

const linkCredTrailAccountFromLtiLaunch = async (input: {
  c: AppContext;
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  sha256Hex: (value: string) => Promise<string>;
}): Promise<ProductFlowResult<LinkedLtiLaunchAccount>> => {
  let linkedAccount: LinkedLtiLaunchAccount;

  try {
    linkedAccount = await linkLtiLaunchAccount({
      db: input.db,
      tenantId: input.tenantId,
      launchClaims: input.launchClaims,
      sha256Hex: input.sha256Hex,
    });
  } catch (error) {
    ltiLogger(input.c)?.warn("Unable to link LTI launch to local account", {
      tenantId: input.tenantId,
      issuer: input.launchClaims.iss,
      hasEmailClaim: ltiEmailFromClaims(input.launchClaims) !== null,
      hasSourcedIdClaim: ltiSourcedIdFromClaims(input.launchClaims) !== null,
      detail: ltiErrorDetail(error),
    });

    return productFlowFailure(accountLinkingFailure(input.c, error));
  }

  return productFlowSuccess(linkedAccount);
};

const establishCredTrailAuthSession = async (input: {
  c: AppContext;
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  ltiLaunchSessionId: string;
  linkedAccount: LinkedLtiLaunchAccount;
  createLtiSession: HandleVerifiedLtiLaunchInput["createLtiSession"];
}): Promise<EstablishedLtiLaunchSession> => {
  const createdSession = await input.createLtiSession(input.c, {
    tenantId: input.tenantId,
    userId: input.linkedAccount.userId,
  });
  await attachLtiLaunchSessionPrincipal(input.db, {
    id: input.ltiLaunchSessionId,
    tenantId: input.tenantId,
    userId: input.linkedAccount.userId,
  });

  return {
    linkedAccount: input.linkedAccount,
    createdSession,
  };
};

/**
 * Handles CredTrail product behavior for a verified LTI Deep Linking launch.
 */
export const handleDeepLinkingLaunch = async (input: {
  c: AppContext;
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  resolvedLaunch: ResolvedLtiLaunch;
  launchMessage: Extract<ValidatedLtiLaunchMessage, { launchMessage: { kind: "deep-linking" } }>;
  establishedSession: EstablishedLtiLaunchSession;
}): Promise<Response> => {
  return renderLtiDeepLinkingLaunchResponse({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.resolvedLaunch.launchClaims,
    launchMessage: input.launchMessage.launchMessage,
    resolvedLaunch: input.resolvedLaunch,
    linkedAccount: input.establishedSession.linkedAccount,
  });
};

/**
 * Handles CredTrail product behavior for a verified LTI Resource Link launch.
 */
export const handleResourceLinkLaunch = async (input: {
  c: AppContext;
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  resolvedLaunch: ResolvedLtiLaunch;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launch: Exclude<ValidatedLtiLaunchMessage, { launchMessage: { kind: "deep-linking" } }>;
  establishedSession: EstablishedLtiLaunchSession;
  sha256Hex: (value: string) => Promise<string>;
}): Promise<Response> => {
  const preparedResourceLinkLaunchResult = await prepareLaunchedResourceLinkPlacement({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    issuerEntryClientId: input.resolvedLaunch.issuerEntry.clientId,
    launchClaims: input.launchClaims,
    resolvedLaunch: input.resolvedLaunch,
    launch: input.launch,
    linkedUserId: input.establishedSession.linkedAccount.userId,
    linkedMembershipRole: input.establishedSession.linkedAccount.membershipRole,
  });

  if (!preparedResourceLinkLaunchResult.ok) {
    return responseFromProductFailure(input.c, preparedResourceLinkLaunchResult.failure);
  }

  const preparedResourceLinkLaunch = preparedResourceLinkLaunchResult.value;
  return renderLtiResourceLinkLaunchResponse({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.launchClaims,
    launchMessage: preparedResourceLinkLaunch.launch.launchMessage,
    linkedAccount: input.establishedSession.linkedAccount,
    establishedSession: input.establishedSession,
    resolvedLaunch: input.resolvedLaunch,
    validatedResourceLinkLaunch: preparedResourceLinkLaunch.launch,
    sha256Hex: input.sha256Hex,
  });
};

/**
 * CredTrail product decisions after an LTI launch is cryptographically verified.
 */
export const handleVerifiedLtiLaunch: HandleVerifiedLtiLaunch = async (input) => {
  const validatedLaunchResult = validateResolvedLtiLaunchMessage({
    launchMessage: input.launchMessage,
  });

  if (!validatedLaunchResult.ok) {
    return responseFromProductFailure(input.c, validatedLaunchResult.failure);
  }

  const validatedLaunchMessage = validatedLaunchResult.value;
  const linkedAccountResult = await linkCredTrailAccountFromLtiLaunch({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.resolvedLaunch.launchClaims,
    sha256Hex: input.sha256Hex,
  });

  if (!linkedAccountResult.ok) {
    return responseFromProductFailure(input.c, linkedAccountResult.failure);
  }

  if (validatedLaunchMessage.launchMessage.roleKind === "instructor") {
    const instructorIdentityResult = await linkInstructorLmsIdentity(input.db, {
      tenantId: input.tenantId,
      issuer: input.resolvedLaunch.launchClaims.iss,
      clientId: input.resolvedLaunch.issuerEntry.clientId,
      deploymentId: input.resolvedLaunch.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
      userId: linkedAccountResult.value.userId,
      providerUserId: input.resolvedLaunch.launchClaims.sub,
    });

    if (!instructorIdentityResult.ok) {
      ltiLogger(input.c)?.warn("Unable to link instructor identity to LMS connection", {
        tenantId: input.tenantId,
        issuer: input.resolvedLaunch.launchClaims.iss,
        errorTag: instructorIdentityResult.error._tag,
        detail: ltiErrorDetail(instructorIdentityResult.error.cause),
      });

      return responseFromProductFailure(
        input.c,
        instructorLmsIdentityFailure(input.c, instructorIdentityResult.error),
      );
    }
  }

  const establishedSession = await establishCredTrailAuthSession({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    ltiLaunchSessionId: input.resolvedLaunch.ltiLaunchSession.id,
    linkedAccount: linkedAccountResult.value,
    createLtiSession: input.createLtiSession,
  });

  input.c.header("Cache-Control", "no-store");

  if (isValidatedDeepLinkingLaunch(validatedLaunchMessage)) {
    return handleDeepLinkingLaunch({
      c: input.c,
      db: input.db,
      tenantId: input.tenantId,
      resolvedLaunch: input.resolvedLaunch,
      launchMessage: validatedLaunchMessage,
      establishedSession,
    });
  }

  return handleResourceLinkLaunch({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.resolvedLaunch.launchClaims,
    resolvedLaunch: input.resolvedLaunch,
    launch: validatedLaunchMessage,
    establishedSession,
    sha256Hex: input.sha256Hex,
  });
};
