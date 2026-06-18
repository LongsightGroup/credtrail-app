import {
  resolveInstructorResourceLinkViews,
  type ResolveInstructorResourceLinkViewsInput,
} from "./instructor-launch-views";
import {
  resolveLearnerResourceLinkView,
  type ResolveLearnerResourceLinkViewInput,
} from "./learner-launch-views";
import type { InstructorResourceLinkViews, LtiLearnerBadgeSummaryView } from "./view-models";

export interface LtiResourceLinkLaunchViews {
  instructorViews: InstructorResourceLinkViews | null;
  learnerView: LtiLearnerBadgeSummaryView | null;
}

export type ResolveLtiResourceLinkLaunchViewsInput =
  | {
      kind: "instructor";
      input: ResolveInstructorResourceLinkViewsInput;
    }
  | {
      kind: "learner";
      input: ResolveLearnerResourceLinkViewInput;
    }
  | {
      kind: "unknown";
    };

export const resolveLtiResourceLinkLaunchViews = async (
  input: ResolveLtiResourceLinkLaunchViewsInput,
): Promise<LtiResourceLinkLaunchViews> => {
  if (input.kind === "instructor") {
    return {
      instructorViews: await resolveInstructorResourceLinkViews(input.input),
      learnerView: null,
    };
  }

  if (input.kind === "learner") {
    return {
      instructorViews: null,
      learnerView: await resolveLearnerResourceLinkView(input.input),
    };
  }

  return {
    instructorViews: null,
    learnerView: null,
  };
};
