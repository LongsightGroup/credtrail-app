import {
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_DEEP_LINKING_SETTINGS,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  resolveLtiRoleKind,
  type LtiLaunchClaims,
  type LtiRoleKind,
} from "@credtrail/lti";
import { asJsonObject, asNonEmptyString } from "../utils/value-parsers";
import type { LtiLaunchState } from "./launch-verification";

const LTI_CLAIM_CUSTOM = "https://purl.imsglobal.org/spec/lti/claim/custom";

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

const parseDeepLinkingSettings = (claimValue: unknown): LtiDeepLinkingSettings | null => {
  const settings = asJsonObject(claimValue);

  if (settings === null) {
    return null;
  }

  const deepLinkReturnUrl = asNonEmptyString(settings.deep_link_return_url);

  if (deepLinkReturnUrl === null) {
    return null;
  }

  let parsedDeepLinkReturnUrl: URL;

  try {
    parsedDeepLinkReturnUrl = new URL(deepLinkReturnUrl);
  } catch {
    return null;
  }

  if (
    parsedDeepLinkReturnUrl.protocol !== "https:" &&
    parsedDeepLinkReturnUrl.protocol !== "http:"
  ) {
    return null;
  }

  let data: string | undefined;

  if (settings.data !== undefined) {
    const parsedData = asNonEmptyString(settings.data);

    if (parsedData === null) {
      return null;
    }

    data = parsedData;
  }

  let acceptTypes: string[] | undefined;

  if (settings.accept_types !== undefined) {
    if (!Array.isArray(settings.accept_types)) {
      return null;
    }

    const normalizedAcceptTypes = settings.accept_types
      .map((entry) => asNonEmptyString(entry))
      .filter((entry): entry is string => entry !== null);

    if (normalizedAcceptTypes.length !== settings.accept_types.length) {
      return null;
    }

    acceptTypes = normalizedAcceptTypes;
  }

  return {
    deepLinkReturnUrl: parsedDeepLinkReturnUrl.toString(),
    ...(data === undefined ? {} : { data }),
    ...(acceptTypes === undefined ? {} : { acceptTypes }),
  };
};

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

export const resolveLtiLaunchMessage = (input: {
  launchClaims: LtiLaunchClaims;
  launchState: LtiLaunchState;
}): ResolvedLtiLaunchMessage => {
  const messageType = input.launchClaims[LTI_CLAIM_MESSAGE_TYPE];
  const targetLinkUriClaim = input.launchClaims[LTI_CLAIM_TARGET_LINK_URI];
  const resolvedTargetLinkUri = targetLinkUriClaim ?? input.launchState.targetLinkUri;
  const roleKind = resolveLtiRoleKind(input.launchClaims);

  if (messageType === LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST) {
    const resourceLinkClaim = input.launchClaims[LTI_CLAIM_RESOURCE_LINK];

    if (resourceLinkClaim === undefined || asNonEmptyString(resourceLinkClaim.id) === null) {
      throw new LtiLaunchMessageError(
        400,
        "id_token for LtiResourceLinkRequest must include resource_link.id",
      );
    }

    return {
      kind: "resource-link",
      messageType,
      roleKind,
      resolvedTargetLinkUri,
      resourceLinkId: resourceLinkClaim.id,
      resourceContextId: asNonEmptyString(asJsonObject(input.launchClaims[LTI_CLAIM_CONTEXT])?.id),
      badgeTemplateId:
        asNonEmptyString(asJsonObject(input.launchClaims[LTI_CLAIM_CUSTOM])?.badgeTemplateId) ??
        badgeTemplateIdFromTargetLinkUri(resolvedTargetLinkUri),
      ruleId:
        asNonEmptyString(asJsonObject(input.launchClaims[LTI_CLAIM_CUSTOM])?.ruleId) ??
        ruleIdFromTargetLinkUri(resolvedTargetLinkUri),
      setupToken:
        asNonEmptyString(asJsonObject(input.launchClaims[LTI_CLAIM_CUSTOM])?.setupToken) ??
        setupTokenFromTargetLinkUri(resolvedTargetLinkUri),
    };
  }

  if (messageType === LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST) {
    if (roleKind !== "instructor") {
      throw new LtiLaunchMessageError(403, "LtiDeepLinkingRequest requires instructor role");
    }

    const deepLinkingSettings = parseDeepLinkingSettings(
      input.launchClaims[LTI_CLAIM_DEEP_LINKING_SETTINGS],
    );

    if (deepLinkingSettings === null) {
      throw new LtiLaunchMessageError(
        400,
        "id_token for LtiDeepLinkingRequest must include deep_linking_settings.deep_link_return_url",
      );
    }

    if (
      deepLinkingSettings.acceptTypes !== undefined &&
      !deepLinkingSettings.acceptTypes.includes("ltiResourceLink")
    ) {
      throw new LtiLaunchMessageError(
        400,
        "deep_linking_settings.accept_types must include ltiResourceLink",
      );
    }

    return {
      kind: "deep-linking",
      messageType,
      roleKind,
      resolvedTargetLinkUri,
      deepLinkingSettings,
    };
  }

  throw new LtiLaunchMessageError(400, `Unsupported LTI message_type: ${messageType}`);
};
