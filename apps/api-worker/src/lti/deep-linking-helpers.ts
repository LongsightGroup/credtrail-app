import {
  createLtiResourceLinkContentItem,
  type DeepLinkingContentItem,
  type LTISession,
} from "@longsightgroup/lti-tool";
import { LTI_DEEP_LINKING_SELECT_PATH } from "./constants";
import type { LtiDeepLinkSelectionPageInput } from "./view-models";

export const badgeRuleDeepLinkContentItem = (input: {
  title: string;
  description: string | null;
  launchUrl: string;
  badgeTemplateId: string;
  ruleId: string;
}): DeepLinkingContentItem => {
  return createLtiResourceLinkContentItem({
    title: input.title,
    text: input.description ?? `CredTrail awarding rule: ${input.title}`,
    url: input.launchUrl,
    custom: {
      badgeTemplateId: input.badgeTemplateId,
      ruleId: input.ruleId,
    },
  });
};

export const ltiDeepLinkSelectionInput = (input: {
  requestUrl: string;
  ltiLaunchSession: LTISession;
  options: LtiDeepLinkSelectionPageInput["options"];
}): LtiDeepLinkSelectionPageInput => {
  return {
    mode: "signed",
    signedSelectionActionUrl: new URL(LTI_DEEP_LINKING_SELECT_PATH, input.requestUrl).toString(),
    ltiSessionId: input.ltiLaunchSession.id,
    courseTitle:
      input.ltiLaunchSession.context.title.trim().length === 0
        ? "this course"
        : input.ltiLaunchSession.context.title,
    options: input.options,
  };
};
