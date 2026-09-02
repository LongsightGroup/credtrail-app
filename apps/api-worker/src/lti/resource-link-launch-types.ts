import type {
  BadgeIssuanceRuleRecord,
  BadgeIssuanceRuleVersionRecord,
  BadgeTemplateRecord,
  LtiResourceLinkPlacementRecord,
} from "@credtrail/db";
import type { ResolvedLtiLaunchMessage } from "./launch-message";

export type ResourceLinkLaunchMessage = Extract<
  ResolvedLtiLaunchMessage,
  { kind: "resource-link" }
>;

export type SelectedResourceLinkLaunchMessage = ResourceLinkLaunchMessage & {
  badgeTemplateId: string;
};

export type CourseResourceLinkLaunchMessage = ResourceLinkLaunchMessage & {
  badgeTemplateId: null;
};

export interface UnresolvedResourceLinkLaunch {
  kind: "unresolved";
  launchMessage: ResourceLinkLaunchMessage;
}

export type ValidatedResourceLinkLaunch =
  | {
      kind: "selected";
      launchMessage: SelectedResourceLinkLaunchMessage;
      launchedBadgeTemplate: BadgeTemplateRecord;
      rule: BadgeIssuanceRuleRecord;
      version: BadgeIssuanceRuleVersionRecord;
      placement: LtiResourceLinkPlacementRecord;
    }
  | {
      kind: "course";
      launchMessage: CourseResourceLinkLaunchMessage;
    };

export type ValidatedSelectedResourceLinkLaunch = Extract<
  ValidatedResourceLinkLaunch,
  { kind: "selected" }
>;

export type ValidatedCourseResourceLinkLaunch = Extract<
  ValidatedResourceLinkLaunch,
  { kind: "course" }
>;
