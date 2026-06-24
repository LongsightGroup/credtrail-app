import type { TenantMembershipRole } from "@credtrail/db";
import type { LtiRoleKind } from "@credtrail/lti";
import type { PropsWithChildren } from "hono/jsx";
import { CtButtonLink } from "../ui/actions";
import { CtCheckboxField, CtField, CtFieldHint, CtForm, CtInput } from "../ui/forms";
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
  userId: string;
}): HonoElement => {
  const thresholdHintId = `score-threshold-hint-${input.option.badgeTemplateId}`;
  const itemHintId = `gradebook-item-hint-${input.option.badgeTemplateId}`;
  const completionHintId = `completion-percent-hint-${input.option.badgeTemplateId}`;

  return (
    <article class="lti-deep-link__option">
      <h2>{input.option.title}</h2>
      <p class="lti-deep-link__meta">Template ID: {input.option.badgeTemplateId}</p>
      {input.option.description === null ? (
        <p class="lti-deep-link__description">No template description provided.</p>
      ) : (
        <p class="lti-deep-link__description">{input.option.description}</p>
      )}
      <p class="lti-deep-link__meta">
        Launch URL:{" "}
        <a href={input.option.launchUrl} target="_blank" rel="noopener noreferrer">
          {input.option.launchUrl}
        </a>
      </p>
      <LtiDeepLinkForm action={input.signedSelectionActionUrl}>
        <CtInput type="hidden" name="lti_session_id" value={input.ltiSessionId} />
        <CtInput type="hidden" name="badge_template_id" value={input.option.badgeTemplateId} />
        <CtInput type="hidden" name="created_by_user_id" value={input.userId} />
        <fieldset class="lti-deep-link__setup">
          <legend>Course earning criteria</legend>
          <div class="lti-deep-link__criteria">
            <CtCheckboxField
              type="radio"
              name="criteria_preset"
              value="manual_instructor_approval"
              label="Manual instructor approval"
              checked={true}
            />
            <CtCheckboxField
              type="radio"
              name="criteria_preset"
              value="final_course_score_threshold"
              label="Final course score threshold"
            />
            <CtCheckboxField
              type="radio"
              name="criteria_preset"
              value="gradebook_item_score_threshold"
              label="Gradebook item score threshold"
            />
            <CtCheckboxField
              type="radio"
              name="criteria_preset"
              value="assignment_submitted_or_graded"
              label="Assignment or assessment submitted or graded"
            />
            <CtCheckboxField
              type="radio"
              name="criteria_preset"
              value="completion_percentage"
              label="Course completion percentage"
            />
          </div>
          <div class="lti-deep-link__setup-fields">
            <CtField label="Score threshold" compact={true}>
              <CtInput
                name="score_threshold"
                type="number"
                value="80"
                min="0"
                max="100"
                step="0.01"
                describedBy={thresholdHintId}
              />
              <CtFieldHint id={thresholdHintId}>Used by score threshold presets.</CtFieldHint>
            </CtField>
            <CtField label="Gradebook item or assignment ID" compact={true}>
              <CtInput
                name="gradebook_item_id"
                type="text"
                placeholder="assignment-123"
                describedBy={itemHintId}
              />
              <CtFieldHint id={itemHintId}>Used by gradebook and assignment presets.</CtFieldHint>
            </CtField>
            <CtField label="Completion percentage" compact={true}>
              <CtInput
                name="completion_percent"
                type="number"
                value="100"
                min="0"
                max="100"
                step="0.01"
                describedBy={completionHintId}
              />
              <CtFieldHint id={completionHintId}>Used by the completion preset.</CtFieldHint>
            </CtField>
          </div>
        </fieldset>
        <div class="lti-deep-link__actions">
          <LtiSubmitButton>Save setup and place badge</LtiSubmitButton>
          <CtButtonLink
            href={input.option.advancedSetupUrl}
            variant="secondary"
            target="_blank"
            rel="noopener noreferrer"
          >
            Advanced setup in CredTrail
          </CtButtonLink>
        </div>
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
          <h1>Select badge template placement</h1>
          <p>Choose a badge template and return it to your LMS via LTI Deep Linking.</p>
        </header>
        <article class="lti-deep-link__details-card">
          <dl class="lti-deep-link__details">
            <DetailRows
              rows={[
                { label: "Issuer", value: input.issuer },
                { label: "Deployment ID", value: input.deploymentId },
                { label: "Tenant", value: input.tenantId },
                { label: "User ID", value: input.userId },
                { label: "Membership role", value: input.membershipRole },
                { label: "Deep link return URL", value: input.deepLinkReturnUrl },
                { label: "Target link URI", value: input.targetLinkUri },
              ]}
            />
          </dl>
        </article>
        <section class="lti-deep-link__options">
          {input.options.length === 0 ? (
            <p class="lti-deep-link__empty">
              No active badge templates are available for this tenant.
            </p>
          ) : (
            input.options.map((option) => (
              <DeepLinkOption
                key={option.badgeTemplateId}
                option={option}
                signedSelectionActionUrl={input.signedSelectionActionUrl}
                ltiSessionId={input.ltiSessionId}
                userId={input.userId}
              />
            ))
          )}
        </section>
      </section>
    ),
  });
};
