import type { BadgeTemplateRecord } from "@credtrail/db";
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

export type ValidatedResourceLinkLaunch =
  | {
      kind: "selected";
      launchMessage: SelectedResourceLinkLaunchMessage;
      launchedBadgeTemplate: BadgeTemplateRecord;
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
