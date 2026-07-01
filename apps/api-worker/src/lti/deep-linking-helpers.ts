import type { DeepLinkingContentItem, LTISession } from "@longsightgroup/lti-tool";
import type { TenantMembershipRole } from "@credtrail/db";
import { LTI_DEEP_LINKING_SELECT_PATH } from "./constants";
import {
  normalizeLtiIssuer,
  type LtiIssuerRegistry,
  type LtiIssuerRegistryEntry,
} from "./lti-helpers";
import type { LtiDeepLinkSelectionPageInput } from "./view-models";

export const findLtiIssuerRegistryEntry = (
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

export const badgeTemplateDeepLinkContentItem = (input: {
  title: string;
  description: string | null;
  launchUrl: string;
  badgeTemplateId: string;
  ruleId?: string | undefined;
  setupToken?: string | undefined;
}): DeepLinkingContentItem => {
  return {
    type: "ltiResourceLink",
    title: input.title,
    text: input.description ?? `CredTrail badge template ${input.title} (${input.badgeTemplateId})`,
    url: input.launchUrl,
    custom: {
      badgeTemplateId: input.badgeTemplateId,
      ...(input.ruleId === undefined ? {} : { ruleId: input.ruleId }),
      ...(input.setupToken === undefined ? {} : { setupToken: input.setupToken }),
    },
  };
};

export const ltiDeepLinkSelectionInput = (input: {
  requestUrl: string;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  issuer: string;
  deploymentId: string;
  deepLinkReturnUrl: string;
  targetLinkUri: string;
  ltiLaunchSession: LTISession;
  badgeTemplates: readonly {
    id: string;
    title: string;
    description: string | null;
  }[];
}): LtiDeepLinkSelectionPageInput => {
  const options = input.badgeTemplates.map((badgeTemplate) => {
    const launchUrl = new URL(input.targetLinkUri);
    launchUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
    const advancedSetupUrl = new URL(
      `/tenants/${encodeURIComponent(input.tenantId)}/admin/rules/new`,
      input.requestUrl,
    );
    advancedSetupUrl.searchParams.set("badgeTemplateId", badgeTemplate.id);
    advancedSetupUrl.searchParams.set("source", "lti-deep-link");

    if (input.ltiLaunchSession.context.id.trim().length > 0) {
      advancedSetupUrl.searchParams.set("ltiContextId", input.ltiLaunchSession.context.id.trim());
    }

    return {
      badgeTemplateId: badgeTemplate.id,
      title: badgeTemplate.title,
      description: badgeTemplate.description,
      launchUrl: launchUrl.toString(),
      advancedSetupUrl: `${advancedSetupUrl.pathname}${advancedSetupUrl.search}`,
    };
  });
  const common = {
    tenantId: input.tenantId,
    userId: input.userId,
    membershipRole: input.membershipRole,
    issuer: input.issuer,
    deploymentId: input.deploymentId,
    deepLinkReturnUrl: input.deepLinkReturnUrl,
    targetLinkUri: input.targetLinkUri,
  };

  return {
    ...common,
    mode: "signed",
    signedSelectionActionUrl: new URL(LTI_DEEP_LINKING_SELECT_PATH, input.requestUrl).toString(),
    ltiSessionId: input.ltiLaunchSession.id,
    options,
  };
};
