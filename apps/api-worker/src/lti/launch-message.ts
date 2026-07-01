import {
  LTI_CLAIM_CUSTOM,
  LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  LtiLaunchMessageResolutionError,
  resolveLtiLaunchMessage as resolveCoreLtiLaunchMessage,
  type LTI13JwtPayload as LtiLaunchClaims,
  type LtiRoleKind as CoreLtiRoleKind,
} from "@longsightgroup/lti-tool";
import { asNonEmptyString } from "../utils/value-parsers";
import type { LtiRoleKind } from "./view-models";

export interface LtiDeepLinkingSettings {
  deepLinkReturnUrl: string;
  data?: string;
  acceptTypes?: string[];
}

export type ResolvedLtiLaunchMessage =
  | {
      kind: "resource-link";
      messageType: typeof LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST;
      roleKind: LtiRoleKind;
      resolvedTargetLinkUri: string;
      resourceLinkId: string;
      resourceContextId: string | null;
      badgeTemplateId: string | null;
      ruleId: string | null;
      setupToken: string | null;
    }
  | {
      kind: "deep-linking";
      messageType: typeof LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST;
      roleKind: LtiRoleKind;
      resolvedTargetLinkUri: string;
      deepLinkingSettings: LtiDeepLinkingSettings;
    };

export class LtiLaunchMessageError extends Error {
  readonly status: 400 | 403;

  constructor(status: 400 | 403, message: string) {
    super(message);
    this.name = "LtiLaunchMessageError";
    this.status = status;
  }
}

export const badgeTemplateIdFromTargetLinkUri = (targetLinkUri: string): string | null => {
  try {
    const parsed = new URL(targetLinkUri);
    const badgeTemplateId = parsed.searchParams.get("badgeTemplateId")?.trim() ?? "";
    return badgeTemplateId.length === 0 ? null : badgeTemplateId;
  } catch {
    return null;
  }
};

export const ruleIdFromTargetLinkUri = (targetLinkUri: string): string | null => {
  try {
    const parsed = new URL(targetLinkUri);
    const ruleId = parsed.searchParams.get("ruleId")?.trim() ?? "";
    return ruleId.length === 0 ? null : ruleId;
  } catch {
    return null;
  }
};

export const setupTokenFromTargetLinkUri = (targetLinkUri: string): string | null => {
  try {
    const parsed = new URL(targetLinkUri);
    const setupToken = parsed.searchParams.get("setupToken")?.trim() ?? "";
    return setupToken.length === 0 ? null : setupToken;
  } catch {
    return null;
  }
};

const credTrailRoleKindFromCoreRoleKinds = (roleKinds: readonly CoreLtiRoleKind[]): LtiRoleKind => {
  if (
    roleKinds.includes("instructor") ||
    roleKinds.includes("content-developer") ||
    roleKinds.includes("administrator")
  ) {
    return "instructor";
  }

  if (roleKinds.includes("learner")) {
    return "learner";
  }

  return "unknown";
};

export const resolveLtiLaunchMessage = (
  launchClaims: LtiLaunchClaims,
): ResolvedLtiLaunchMessage => {
  let coreLaunchMessage: ReturnType<typeof resolveCoreLtiLaunchMessage>;

  try {
    coreLaunchMessage = resolveCoreLtiLaunchMessage(launchClaims);
  } catch (error) {
    if (error instanceof LtiLaunchMessageResolutionError) {
      throw new LtiLaunchMessageError(400, error.message);
    }

    throw error;
  }

  const resolvedTargetLinkUri = coreLaunchMessage.targetLinkUri;
  const roleKind = credTrailRoleKindFromCoreRoleKinds(coreLaunchMessage.roleKinds);

  if (coreLaunchMessage.kind === "resource-link") {
    const customParameters = launchClaims[LTI_CLAIM_CUSTOM] ?? {};

    return {
      kind: "resource-link",
      messageType: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
      roleKind,
      resolvedTargetLinkUri,
      resourceLinkId: coreLaunchMessage.resourceLink.id,
      resourceContextId: coreLaunchMessage.context?.id ?? null,
      badgeTemplateId:
        asNonEmptyString(customParameters.badgeTemplateId) ??
        badgeTemplateIdFromTargetLinkUri(resolvedTargetLinkUri),
      ruleId:
        asNonEmptyString(customParameters.ruleId) ?? ruleIdFromTargetLinkUri(resolvedTargetLinkUri),
      setupToken:
        asNonEmptyString(customParameters.setupToken) ??
        setupTokenFromTargetLinkUri(resolvedTargetLinkUri),
    };
  }

  if (coreLaunchMessage.kind === "deep-linking") {
    if (roleKind !== "instructor") {
      throw new LtiLaunchMessageError(403, "LtiDeepLinkingRequest requires instructor role");
    }

    const deepLinkingSettings = coreLaunchMessage.deepLinkingSettings;

    if (!deepLinkingSettings.acceptTypes.includes("ltiResourceLink")) {
      throw new LtiLaunchMessageError(
        400,
        "deep_linking_settings.accept_types must include ltiResourceLink",
      );
    }

    return {
      kind: "deep-linking",
      messageType: LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
      roleKind,
      resolvedTargetLinkUri,
      deepLinkingSettings: {
        deepLinkReturnUrl: deepLinkingSettings.returnUrl,
        ...(deepLinkingSettings.data === undefined ? {} : { data: deepLinkingSettings.data }),
        acceptTypes: deepLinkingSettings.acceptTypes,
      },
    };
  }

  throw new LtiLaunchMessageError(400, "Unsupported LTI message_type");
};
