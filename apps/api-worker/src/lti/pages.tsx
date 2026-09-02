import type { TenantMembershipRole } from "@credtrail/db";
import type { PropsWithChildren } from "hono/jsx";
import { CtForm, CtInput } from "../ui/forms";
import { appPage, type AppPage } from "../ui/render-page";
import type { PageAssetKey } from "../ui/page-assets";
import { BulkIssuanceSection, CourseBadgeSummarySection } from "./instructor-launch-pages";
import { LearnerBadgeSummarySection } from "./learner-launch-pages";
import {
  DetailRows,
  type HonoElement,
  LtiLaunchCard,
  LtiSubmitButton,
} from "./launch-page-components";
import {
  ltiLaunchViewMode,
  type InstructorResourceLinkViews,
  type LtiDeepLinkSelectionPageInput,
  type LtiDeepLinkSelectionOption,
  type LtiLearnerBadgeSummaryView,
  type LtiLaunchViewMode,
  type LtiRoleKind,
  type LtiRosterIssuanceResultEntry,
} from "./view-models";

export type {
  InstructorResourceLinkViews,
  LtiBadgeSummaryCard,
  LtiBulkIssuanceRosterMember,
  LtiBulkIssuanceView,
  LtiCourseBadgeSummaryRow,
  LtiCourseBadgeSummaryView,
  LtiDeepLinkSelectionPageInput,
  LtiLearnerBadgeSummaryView,
  LtiRosterIssuanceResultEntry,
} from "./view-models";

const ltiPage = (input: {
  title: string;
  body: HonoElement;
  scripts?: readonly PageAssetKey[];
}): AppPage => {
  return appPage({
    title: input.title,
    body: input.body,
    assets: input.scripts === undefined ? ["ltiPagesCss"] : ["ltiPagesCss", ...input.scripts],
  });
};

const LtiDeepLinkForm = ({
  action,
  children,
}: PropsWithChildren<{
  action: string;
}>): HonoElement => {
  return (
    <CtForm method="post" action={action} className="lti-deep-link__form">
      {children}
    </CtForm>
  );
};

const ltiLaunchTitle = (input: {
  mode: LtiLaunchViewMode;
  launchDisplayName: string | null;
}): string => {
  if (input.mode === "bulkReady") {
    if (input.launchDisplayName !== null) {
      return `Hi, ${input.launchDisplayName}`;
    }

    return "Issue badges from this LMS course";
  }

  if (input.mode === "bulkDegraded") {
    return "CredTrail could not load this LMS roster";
  }

  if (input.mode === "courseSummaryReady") {
    if (input.launchDisplayName !== null) {
      return `Hi, ${input.launchDisplayName}`;
    }

    return "Review badge progress for this course";
  }

  if (input.mode === "courseSummaryDegraded") {
    return "CredTrail could not load badge progress";
  }

  if (input.mode === "learner") {
    if (input.launchDisplayName !== null) {
      return `Hi, ${input.launchDisplayName}`;
    }

    return "Your CredTrail badges";
  }

  if (input.mode === "learnerDegraded") {
    return "CredTrail could not load badge details";
  }

  return "CredTrail is connected";
};

const ltiLaunchSubtitle = (input: { mode: LtiLaunchViewMode }): string => {
  if (input.mode === "bulkReady") {
    return "Review the selected badge, then choose learners from this course roster to issue it.";
  }

  if (input.mode === "bulkDegraded") {
    return "Open CredTrail or ask an administrator to check the LMS roster connection.";
  }

  if (input.mode === "courseSummaryReady") {
    return "Review badge progress for this course from the LMS roster.";
  }

  if (input.mode === "courseSummaryDegraded") {
    return "Open CredTrail or ask an administrator to check the LMS roster connection.";
  }

  if (input.mode === "learner") {
    return "Your LMS account is linked to CredTrail.";
  }

  if (input.mode === "learnerDegraded") {
    return "Your LMS account is linked. Open your dashboard to review issued badges and sharing options.";
  }

  return "Your LMS account is linked to CredTrail.";
};

const ltiSessionHandoffTokenFromPath = (path: string): string | null => {
  const url = new URL(path, "https://credtrail.local");
  return url.searchParams.get("lti_session_handoff");
};

export const ltiPostMessageStorageRedirectPage = (input: {
  authorizationRedirectUrl: string;
  platformOrigin: string;
  storageTarget: string;
  state: string;
  nonce: string;
}): AppPage => {
  return ltiPage({
    title: "LTI Launch Redirect | CredTrail",
    scripts: ["ltiPostMessageStorageJs"],
    body: (
      <section
        id="lti-post-message-storage-redirect"
        class="lti-launch"
        data-authorization-redirect-url={input.authorizationRedirectUrl}
        data-platform-origin={input.platformOrigin}
        data-storage-target={input.storageTarget}
        data-state={input.state}
        data-nonce={input.nonce}
      >
        <p class="lti-launch__sr-only" role="status" aria-live="polite">
          Continuing LTI launch.
        </p>
      </section>
    ),
  });
};

export const ltiLaunchResultPage = (input: {
  roleKind: LtiRoleKind;
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  learnerProfileId: string;
  issuer: string;
  deploymentId: string;
  subjectId: string;
  targetLinkUri: string;
  messageType: string;
  launchDisplayName: string | null;
  dashboardPath: string;
  instructorViews: InstructorResourceLinkViews | null;
  learnerView: LtiLearnerBadgeSummaryView | null;
}): AppPage => {
  const mode = ltiLaunchViewMode({
    roleKind: input.roleKind,
    instructorViews: input.instructorViews,
    learnerView: input.learnerView,
  });
  const bulkIssuanceView = input.instructorViews?.bulkIssuanceView ?? null;
  const courseBadgeSummaryView = input.instructorViews?.courseBadgeSummaryView ?? null;
  const isLearnerMode = mode === "learner" || mode === "learnerDegraded";
  const showDashboardAction =
    isLearnerMode ||
    mode === "connected" ||
    mode === "bulkDegraded" ||
    mode === "courseSummaryDegraded";
  const scripts = courseBadgeSummaryView === null ? undefined : (["ltiCourseSummaryJs"] as const);
  const title = ltiLaunchTitle({
    mode,
    launchDisplayName: input.launchDisplayName,
  });
  const sessionHandoffToken = isLearnerMode
    ? ltiSessionHandoffTokenFromPath(input.dashboardPath)
    : null;

  return ltiPage({
    title: `${title} | CredTrail`,
    ...(scripts === undefined ? {} : { scripts }),
    body: (
      <section class="lti-launch">
        <header class="lti-launch__hero">
          <h1>{title}</h1>
          <p>{ltiLaunchSubtitle({ mode })}</p>
        </header>
        <BulkIssuanceSection view={bulkIssuanceView} />
        <CourseBadgeSummarySection view={courseBadgeSummaryView} />
        {showDashboardAction ? (
          <LtiLaunchCard stack={true}>
            <p class="lti-launch__hint">Continue in CredTrail when you are ready.</p>
            <p class="lti-launch__link-row">
              <a href={input.dashboardPath} target="_blank" rel="noopener noreferrer">
                Open CredTrail dashboard
              </a>
            </p>
          </LtiLaunchCard>
        ) : null}
        <LearnerBadgeSummarySection
          view={input.learnerView}
          sessionHandoffToken={sessionHandoffToken}
        />
        {isLearnerMode ? null : (
          <details class="lti-launch__technical-details">
            <summary>Launch troubleshooting details</summary>
            <dl class="lti-launch__details">
              <DetailRows
                rows={[
                  { label: "LMS", value: input.issuer },
                  { label: "Deployment ID", value: input.deploymentId },
                  { label: "Tenant", value: input.tenantId },
                  { label: "User ID", value: input.userId },
                  { label: "Membership role", value: input.membershipRole },
                  { label: "CredTrail learner profile", value: input.learnerProfileId },
                  { label: "LTI subject", value: input.subjectId },
                  { label: "Message type", value: input.messageType },
                  { label: "Launch URL", value: input.targetLinkUri },
                ]}
              />
            </dl>
          </details>
        )}
      </section>
    ),
  });
};

export const ltiRuleUnavailablePage = (input: { readonly message: string }): AppPage => {
  return ltiPage({
    title: "Badge rule unavailable | CredTrail",
    body: (
      <section class="lti-launch">
        <header class="lti-launch__hero">
          <h1>This badge rule isn’t available in this course</h1>
          <p>{input.message}</p>
        </header>
        <LtiLaunchCard stack={true}>
          <p>
            Contact the course instructor or your institution’s CredTrail administrator to update
            this LMS link or its course availability.
          </p>
        </LtiLaunchCard>
      </section>
    ),
  });
};

export const ltiRosterIssuanceResultPage = (input: {
  tenantId: string;
  badgeTemplateId: string;
  courseContextTitle: string | null;
  selectedCount: number;
  results: readonly LtiRosterIssuanceResultEntry[];
}): AppPage => {
  const issuedCount = input.results.filter((entry) => entry.status === "issued").length;
  const alreadyIssuedCount = input.results.filter(
    (entry) => entry.status === "already_issued",
  ).length;
  const skippedCount = input.results.filter((entry) => entry.status === "skipped").length;
  const failedCount = input.results.filter((entry) => entry.status === "failed").length;

  return ltiPage({
    title: "LTI Badge Issuance | CredTrail",
    body: (
      <section class="lti-launch">
        <header class="lti-launch__hero">
          <h1>Badge issuance complete</h1>
          <p>Processed selected learners for the placed badge.</p>
        </header>
        <LtiLaunchCard stack={true}>
          <dl class="lti-launch__details">
            <DetailRows
              rows={[
                { label: "Tenant", value: input.tenantId },
                { label: "Badge template", value: input.badgeTemplateId },
                { label: "Course context", value: input.courseContextTitle ?? "Not provided" },
                { label: "Selected learners", value: input.selectedCount },
                { label: "Issued", value: issuedCount },
                { label: "Already issued", value: alreadyIssuedCount },
                { label: "Skipped", value: skippedCount },
                { label: "Failed", value: failedCount },
              ]}
            />
          </dl>
          <div class="lti-launch__bulk-table-wrap">
            <table class="lti-launch__bulk-table">
              <thead>
                <tr>
                  <th>Learner</th>
                  <th>Email</th>
                  <th>Status</th>
                  <th>Message</th>
                  <th>Assertion</th>
                </tr>
              </thead>
              <tbody>
                {input.results.length === 0 ? (
                  <tr>
                    <td colspan={5} class="lti-launch__bulk-empty">
                      No learners were selected.
                    </td>
                  </tr>
                ) : (
                  input.results.map((entry) => (
                    <tr key={entry.userId}>
                      <td>{entry.displayName ?? entry.userId}</td>
                      <td>{entry.email ?? "Not provided"}</td>
                      <td>{entry.status}</td>
                      <td>{entry.message}</td>
                      <td>{entry.assertionId ?? "Not created"}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </LtiLaunchCard>
      </section>
    ),
  });
};

const DeepLinkOption = (input: {
  option: LtiDeepLinkSelectionOption;
  signedSelectionActionUrl: string;
  ltiSessionId: string;
}): HonoElement => {
  return (
    <article class="lti-deep-link__option">
      <div class="lti-deep-link__option-heading">
        <div>
          <p class="lti-deep-link__eyebrow">{input.option.badgeTitle}</p>
          <h2>{input.option.ruleName}</h2>
        </div>
        <span class="lti-deep-link__version">Version {String(input.option.versionNumber)}</span>
      </div>
      {input.option.badgeDescription === null ? (
        <p class="lti-deep-link__description">No badge description provided.</p>
      ) : (
        <p class="lti-deep-link__description">{input.option.badgeDescription}</p>
      )}
      <dl class="lti-deep-link__rule-summary">
        <div>
          <dt>Requirements</dt>
          <dd>{input.option.requirementSummary}</dd>
        </div>
      </dl>
      <LtiDeepLinkForm action={input.signedSelectionActionUrl}>
        <CtInput type="hidden" name="lti_session_id" value={input.ltiSessionId} />
        <CtInput type="hidden" name="rule_id" value={input.option.ruleId} />
        <LtiSubmitButton>Add to this course</LtiSubmitButton>
      </LtiDeepLinkForm>
    </article>
  );
};

export const ltiDeepLinkSelectionPage = (input: LtiDeepLinkSelectionPageInput): AppPage => {
  return ltiPage({
    title: "LTI Deep Linking | CredTrail",
    body: (
      <section class="lti-deep-link">
        <header class="lti-deep-link__hero">
          <p class="lti-deep-link__eyebrow">{input.courseTitle}</p>
          <h1>Add a badge rule</h1>
          <p>Choose a governed awarding rule that your institution offers in this course.</p>
        </header>
        <section class="lti-deep-link__options">
          {input.options.length === 0 ? (
            <p class="lti-deep-link__empty">
              No badge rules are currently offered in this course. Contact your institution’s
              CredTrail administrator.
            </p>
          ) : (
            input.options.map((option) => (
              <DeepLinkOption
                key={option.ruleId}
                option={option}
                signedSelectionActionUrl={input.signedSelectionActionUrl}
                ltiSessionId={input.ltiSessionId}
              />
            ))
          )}
        </section>
      </section>
    ),
  });
};
