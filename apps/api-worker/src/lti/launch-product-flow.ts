import { attachLtiLaunchSessionPrincipal } from "@credtrail/db";
import type { AppContext } from "../app";
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
  logResourceLinkPlacementFailure,
  prepareLaunchedResourceLinkPlacement,
  renderLtiResourceLinkLaunchResponse,
  validateLaunchedResourceLinkBadgeTemplate,
} from "./launch-resource-link-flow";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { ltiLogger } from "./log";
import { ltiEmailFromClaims, ltiSourcedIdFromClaims } from "./lti-helpers";

export type { HandleVerifiedLtiLaunch, HandleVerifiedLtiLaunchInput };

const isValidatedDeepLinkingLaunch = (
  launch: ValidatedLtiLaunchMessage,
): launch is Extract<ValidatedLtiLaunchMessage, { launchMessage: { kind: "deep-linking" } }> => {
  return launch.launchMessage.kind === "deep-linking";
};

export const responseFromProductFailure = (
  c: AppContext,
  failure: ProductFlowFailure,
): Response => {
  return c.json(failure.body, failure.status);
};

const validateResolvedLtiLaunchMessage = async (input: {
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  launchMessage: ResolvedLtiLaunchMessage;
}): Promise<ProductFlowResult<ValidatedLtiLaunchMessage>> => {
  if (input.launchMessage.kind === "deep-linking") {
    return productFlowSuccess({
      launchMessage: input.launchMessage,
    });
  }

  return validateLaunchedResourceLinkBadgeTemplate({
    db: input.db,
    tenantId: input.tenantId,
    launchMessage: input.launchMessage,
  });
};

const accountLinkingFailure = (c: AppContext, error: unknown): ProductFlowFailure => {
  const detail = error instanceof Error ? error.message : "unknown error";

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
      detail,
    },
  };
};

/**
 * Links the verified LTI launch to CredTrail identity and creates a browser auth session.
 */
export const createCredTrailAuthSessionFromLtiLaunch = async (input: {
  c: AppContext;
  db: HandleVerifiedLtiLaunchInput["db"];
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: ResolvedLtiLaunchMessage;
  ltiLaunchSession: ResolvedLtiLaunch["ltiLaunchSession"];
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: HandleVerifiedLtiLaunchInput["createLtiSession"];
}): Promise<ProductFlowResult<EstablishedLtiLaunchSession>> => {
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
      roleKind: input.launchMessage.roleKind,
      issuer: input.launchClaims.iss,
      hasEmailClaim: ltiEmailFromClaims(input.launchClaims) !== null,
      hasSourcedIdClaim: ltiSourcedIdFromClaims(input.launchClaims) !== null,
      detail: error instanceof Error ? error.message : "unknown error",
    });

    return productFlowFailure(accountLinkingFailure(input.c, error));
  }

  const createdSession = await input.createLtiSession(input.c, {
    tenantId: input.tenantId,
    userId: linkedAccount.userId,
  });
  await attachLtiLaunchSessionPrincipal(input.db, {
    id: input.ltiLaunchSession.id,
    tenantId: input.tenantId,
    userId: linkedAccount.userId,
  });

  return productFlowSuccess({
    linkedAccount,
    createdSession,
  });
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

  if (preparedResourceLinkLaunch.placementResult !== null) {
    logResourceLinkPlacementFailure({
      c: input.c,
      tenantId: input.tenantId,
      launch: preparedResourceLinkLaunch.launch,
      placementResult: preparedResourceLinkLaunch.placementResult,
    });
  }

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
  const validatedLaunchResult = await validateResolvedLtiLaunchMessage({
    db: input.db,
    tenantId: input.tenantId,
    launchMessage: input.launchMessage,
  });

  if (!validatedLaunchResult.ok) {
    return responseFromProductFailure(input.c, validatedLaunchResult.failure);
  }

  const validatedLaunchMessage = validatedLaunchResult.value;
  const establishedSessionResult = await createCredTrailAuthSessionFromLtiLaunch({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.resolvedLaunch.launchClaims,
    launchMessage: validatedLaunchMessage.launchMessage,
    ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
    sha256Hex: input.sha256Hex,
    createLtiSession: input.createLtiSession,
  });

  if (!establishedSessionResult.ok) {
    return responseFromProductFailure(input.c, establishedSessionResult.failure);
  }

  input.c.header("Cache-Control", "no-store");

  if (isValidatedDeepLinkingLaunch(validatedLaunchMessage)) {
    return handleDeepLinkingLaunch({
      c: input.c,
      db: input.db,
      tenantId: input.tenantId,
      resolvedLaunch: input.resolvedLaunch,
      launchMessage: validatedLaunchMessage,
      establishedSession: establishedSessionResult.value,
    });
  }

  return handleResourceLinkLaunch({
    c: input.c,
    db: input.db,
    tenantId: input.tenantId,
    launchClaims: input.resolvedLaunch.launchClaims,
    resolvedLaunch: input.resolvedLaunch,
    launch: validatedLaunchMessage,
    establishedSession: establishedSessionResult.value,
    sha256Hex: input.sha256Hex,
  });
};
