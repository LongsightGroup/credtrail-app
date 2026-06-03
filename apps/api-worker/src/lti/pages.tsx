import type { TenantMembershipRole } from "@credtrail/db";
import type { LtiRoleKind } from "@credtrail/lti";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";
import type { PageAssetKey } from "../ui/page-assets";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

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

const LtiLaunchCard = ({
  stack,
  children,
}: PropsWithChildren<{
  stack?: boolean;
}>): HonoElement => {
  const className =
    stack === true ? "lti-launch__card lti-launch__card--stack" : "lti-launch__card";

  return <article class={className}>{children}</article>;
};

const LtiSubmitButton = ({
  disabled,
  children,
}: PropsWithChildren<{
  disabled?: boolean;
}>): HonoElement => {
  return (
    <button type="submit" disabled={disabled === true}>
      {children}
    </button>
  );
};

const LtiDeepLinkForm = ({
  action,
  children,
}: PropsWithChildren<{
  action: string;
}>): HonoElement => {
  return (
    <form method="post" action={action} class="lti-deep-link__form">
      {children}
    </form>
  );
};

type LtiLaunchViewMode =
  | "learner"
  | "bulkReady"
  | "bulkDegraded"
  | "courseSummaryReady"
  | "courseSummaryDegraded"
  | "connected";

const ltiLaunchViewMode = (input: {
  roleKind: LtiRoleKind;
  bulkIssuanceView: LtiBulkIssuanceView | null;
  courseBadgeSummaryView: LtiCourseBadgeSummaryView | null;
}): LtiLaunchViewMode => {
  if (input.roleKind === "learner") {
    return "learner";
  }

  if (input.roleKind === "instructor" && input.bulkIssuanceView !== null) {
    return input.bulkIssuanceView.status === "ready" ? "bulkReady" : "bulkDegraded";
  }

  if (input.roleKind === "instructor" && input.courseBadgeSummaryView !== null) {
    return input.courseBadgeSummaryView.status === "ready"
      ? "courseSummaryReady"
      : "courseSummaryDegraded";
  }

  return "connected";
};

const ltiLaunchTitle = (input: {
  mode: LtiLaunchViewMode;
  launchDisplayName: string | null;
}): string => {
  if (input.mode === "bulkReady") {
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
    return "Open your CredTrail dashboard";
  }

  return "CredTrail is connected";
};

const ltiLaunchSubtitle = (input: { mode: LtiLaunchViewMode }): string => {
  if (input.mode === "bulkReady") {
    return "Select learners below to issue the badge placed in this LMS tool.";
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
    return "Your LMS account is linked and this browser is signed in.";
  }

  return "Your LMS account is linked and this browser is signed in.";
};

const DetailRows = (input: {
  rows: readonly {
    label: string;
    value: string | number;
  }[];
}): HonoElement => {
  return (
    <>
      {input.rows.map((row) => (
        <>
          <dt>{row.label}</dt>
          <dd>{String(row.value)}</dd>
        </>
      ))}
    </>
  );
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
        <header class="lti-launch__hero">
          <h1>Continuing LTI launch</h1>
        </header>
      </section>
    ),
  });
};

export interface LtiBulkIssuanceRosterMember {
  userId: string;
  sourcedId: string | null;
  displayName: string | null;
  email: string | null;
  roleSummary: string;
  status: string | null;
  issuedAssertionId: string | null;
  issuedAt: string | null;
  issuanceLifecycleState: "active" | "suspended" | "revoked" | "expired" | null;
}

export interface LtiBulkIssuanceView {
  status: "ready" | "unavailable" | "error";
  message: string;
  badgeTemplateId: string | null;
  courseContextTitle: string | null;
  courseContextId: string | null;
  contextMembershipsUrl: string | null;
  learnerCount: number;
  totalCount: number;
  issuanceActionPath: string | null;
  issuanceActionToken: string | null;
  members: readonly LtiBulkIssuanceRosterMember[];
}

export interface LtiCourseBadgeSummaryRow {
  learnerUserId: string;
  learnerName: string;
  learnerEmail: string | null;
  learnerDetailPath: string | null;
  badgeTemplateId: string;
  badgeTitle: string;
  badgeDetailPath: string;
  status: "issued" | "not_issued" | "suspended" | "revoked" | "expired";
  statusLabel: string;
  statusDetail: string;
  assertionId: string | null;
  issuedAt: string | null;
}

export interface LtiCourseBadgeSummaryView {
  status: "ready" | "unavailable" | "error";
  message: string;
  courseContextTitle: string | null;
  learnerCount: number;
  badgeCount: number;
  issuedCount: number;
  rows: readonly LtiCourseBadgeSummaryRow[];
}

export interface LtiRosterIssuanceResultEntry {
  userId: string;
  displayName: string | null;
  email: string | null;
  status: "issued" | "already_issued" | "skipped" | "failed";
  message: string;
  assertionId: string | null;
}

interface LtiDeepLinkSelectionBaseInput {
  tenantId: string;
  userId: string;
  membershipRole: TenantMembershipRole;
  issuer: string;
  deploymentId: string;
  deepLinkReturnUrl: string;
  targetLinkUri: string;
}

interface LtiDeepLinkSelectionOption {
  badgeTemplateId: string;
  title: string;
  description: string | null;
  launchUrl: string;
}

export type LtiDeepLinkSelectionPageInput = LtiDeepLinkSelectionBaseInput & {
  mode: "signed";
  signedSelectionActionUrl: string;
  ltiSessionId: string;
  options: readonly LtiDeepLinkSelectionOption[];
};

const BulkIssuanceSection = (input: { view: LtiBulkIssuanceView | null }): HonoElement | null => {
  if (input.view === null) {
    return null;
  }

  const view = input.view;
  const canIssue =
    view.status === "ready" &&
    view.badgeTemplateId !== null &&
    view.issuanceActionPath !== null &&
    view.issuanceActionToken !== null;
  const missingEmailCount = view.members.filter((member) => member.email === null).length;
  const alreadyIssuedCount = view.members.filter(
    (member) => member.issuedAssertionId !== null,
  ).length;
  const selectableCount = view.members.filter(
    (member) => member.email !== null && member.issuedAssertionId === null,
  ).length;
  const badgeIssuanceStatus = (member: LtiBulkIssuanceRosterMember): string => {
    if (member.issuedAssertionId === null) {
      return "Not issued";
    }

    if (member.issuanceLifecycleState === null || member.issuanceLifecycleState === "active") {
      return `Already issued: ${member.issuedAssertionId}`;
    }

    return `Already issued (${member.issuanceLifecycleState}): ${member.issuedAssertionId}`;
  };
  const table = (
    <div class="lti-launch__bulk-table-wrap">
      <table class="lti-launch__bulk-table">
        <thead>
          <tr>
            {canIssue ? <th>Select</th> : null}
            <th>Learner</th>
            <th>Email</th>
            <th>Badge</th>
          </tr>
        </thead>
        <tbody>
          {view.members.length === 0 ? (
            <tr>
              <td colspan={canIssue ? 4 : 3} class="lti-launch__bulk-empty">
                No learners returned by LMS roster for this launch.
              </td>
            </tr>
          ) : (
            view.members.map((member) => (
              <tr key={member.userId}>
                {canIssue ? (
                  <td>
                    <input
                      type="checkbox"
                      name="learner_user_id"
                      value={member.userId}
                      disabled={member.email === null || member.issuedAssertionId !== null}
                    />
                  </td>
                ) : null}
                <td>{member.displayName ?? member.userId}</td>
                <td>{member.email ?? "Not provided"}</td>
                <td>{badgeIssuanceStatus(member)}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );

  return (
    <LtiLaunchCard stack={true}>
      <h2 class="lti-launch__bulk-title">Issue badges from course roster</h2>
      <p class="lti-launch__hint">Select learners and issue the badge placed in this LMS tool.</p>
      <p class={`lti-launch__bulk-status lti-launch__bulk-status--${view.status}`}>
        {view.message}
      </p>
      <dl class="lti-launch__bulk-meta">
        <DetailRows
          rows={[
            {
              label: "Course",
              value: view.courseContextTitle ?? "Not provided",
            },
            {
              label: "Learners",
              value: `${String(view.learnerCount)} of ${String(view.totalCount)}`,
            },
            {
              label: "Issued in this launch item",
              value: `${String(alreadyIssuedCount)} of ${String(view.learnerCount)}`,
            },
            {
              label: "Selectable learners",
              value: selectableCount,
            },
          ]}
        />
      </dl>
      {canIssue ? (
        <form method="post" action={view.issuanceActionPath ?? ""} class="lti-launch__bulk-form">
          <input
            type="hidden"
            name="issuance_action_token"
            value={view.issuanceActionToken ?? ""}
          />
          {table}
          <div class="lti-launch__bulk-actions">
            {missingEmailCount === 0 ? null : (
              <p class="lti-launch__hint">
                {String(missingEmailCount)} learner{missingEmailCount === 1 ? "" : "s"} cannot be
                selected because the LMS did not provide an email address.
              </p>
            )}
            <LtiSubmitButton disabled={selectableCount === 0}>
              Issue selected badges
            </LtiSubmitButton>
          </div>
        </form>
      ) : (
        table
      )}
    </LtiLaunchCard>
  );
};

const CourseBadgeSummarySection = (input: {
  view: LtiCourseBadgeSummaryView | null;
}): HonoElement | null => {
  if (input.view === null) {
    return null;
  }

  const view = input.view;
  const badgeOptions = Array.from(
    new Map(view.rows.map((row): [string, string] => [row.badgeTemplateId, row.badgeTitle])),
  ).map(([badgeTemplateId, badgeTitle]) => ({ badgeTemplateId, badgeTitle }));
  const hasRows = view.rows.length > 0;

  return (
    <LtiLaunchCard stack={true}>
      <div class="lti-launch__course-summary" data-lti-course-summary>
        <header class="lti-launch__section-head">
          <h2 class="lti-launch__bulk-title">Course badge summary</h2>
          <p class="lti-launch__hint">Search learners, badges, or status in this course.</p>
        </header>
        <p class={`lti-launch__bulk-status lti-launch__bulk-status--${view.status}`}>
          {view.message}
        </p>
        <dl class="lti-launch__bulk-meta lti-launch__bulk-meta--summary">
          <DetailRows
            rows={[
              {
                label: "Course",
                value: view.courseContextTitle ?? "Not provided",
              },
              {
                label: "Learners",
                value: view.learnerCount,
              },
              {
                label: "Badges",
                value: view.badgeCount,
              },
              {
                label: "Issued badges",
                value: view.issuedCount,
              },
            ]}
          />
        </dl>
        {hasRows ? (
          <div class="lti-launch__summary-controls">
            <label class="lti-launch__summary-field">
              <span>Search</span>
              <input
                type="search"
                data-lti-course-summary-search
                placeholder="Learner, email, badge, or status"
              />
            </label>
            <label class="lti-launch__summary-field">
              <span>Badge</span>
              <select data-lti-course-summary-badge-filter>
                <option value="">All badges</option>
                {badgeOptions.map((badge) => (
                  <option value={badge.badgeTemplateId}>{badge.badgeTitle}</option>
                ))}
              </select>
            </label>
            <label class="lti-launch__summary-field">
              <span>Status</span>
              <select data-lti-course-summary-status-filter>
                <option value="">All statuses</option>
                <option value="issued">Issued</option>
                <option value="not_issued">Not issued</option>
                <option value="suspended">Suspended</option>
                <option value="revoked">Revoked</option>
                <option value="expired">Expired</option>
              </select>
            </label>
            <p class="lti-launch__summary-count">
              <span data-lti-course-summary-count>{String(view.rows.length)}</span> rows
            </p>
          </div>
        ) : null}
        <div class="lti-launch__bulk-table-wrap">
          <table class="lti-launch__bulk-table lti-launch__summary-table">
            <caption>Badge progress for learners in this LMS course</caption>
            <thead>
              <tr>
                <th scope="col">Learner</th>
                <th scope="col">Email</th>
                <th scope="col">Badge</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
            <tbody>
              {hasRows ? (
                <>
                  {view.rows.map((row) => {
                    const searchText = [
                      row.learnerName,
                      row.learnerEmail ?? "",
                      row.badgeTitle,
                      row.statusLabel,
                      row.statusDetail,
                    ].join(" ");

                    return (
                      <tr
                        key={`${row.learnerUserId}:${row.badgeTemplateId}`}
                        data-lti-course-summary-row
                        data-search-text={searchText}
                        data-badge-template-id={row.badgeTemplateId}
                        data-status={row.status}
                      >
                        <td>
                          {row.learnerDetailPath === null ? (
                            row.learnerName
                          ) : (
                            <a
                              href={row.learnerDetailPath}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              {row.learnerName}
                              <span class="lti-launch__sr-only">
                                {" "}
                                badge record for {row.badgeTitle}
                              </span>
                            </a>
                          )}
                        </td>
                        <td>{row.learnerEmail ?? "Not provided"}</td>
                        <td>
                          <a href={row.badgeDetailPath} target="_blank" rel="noopener noreferrer">
                            {row.badgeTitle}
                            <span class="lti-launch__sr-only"> badge setup for this course</span>
                          </a>
                        </td>
                        <td>
                          <div class="lti-launch__status-stack">
                            <span
                              class={`lti-launch__status-pill lti-launch__status-pill--${row.status}`}
                            >
                              {row.statusLabel}
                            </span>
                            {row.issuedAt === null ? null : (
                              <span class="lti-launch__summary-timestamp">
                                Issued {row.issuedAt}
                              </span>
                            )}
                            <span class="lti-launch__summary-status-detail">
                              {row.statusDetail}
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  <tr data-lti-course-summary-empty hidden>
                    <td colspan={4} class="lti-launch__bulk-empty">
                      No learners or badges match those filters.
                    </td>
                  </tr>
                </>
              ) : (
                <tr>
                  <td colspan={4} class="lti-launch__bulk-empty">
                    No course badge rows are available yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </LtiLaunchCard>
  );
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
  bulkIssuanceView: LtiBulkIssuanceView | null;
  courseBadgeSummaryView: LtiCourseBadgeSummaryView | null;
}): AppPage => {
  const mode = ltiLaunchViewMode(input);
  const showDashboardAction =
    mode === "learner" ||
    mode === "connected" ||
    mode === "bulkDegraded" ||
    mode === "courseSummaryDegraded";
  const scripts =
    input.courseBadgeSummaryView === null ? undefined : (["ltiCourseSummaryJs"] as const);
  const title = ltiLaunchTitle({
    mode,
    launchDisplayName: input.launchDisplayName,
  });

  return ltiPage({
    title: `${title} | CredTrail`,
    ...(scripts === undefined ? {} : { scripts }),
    body: (
      <section class="lti-launch">
        <header class="lti-launch__hero">
          <h1>{title}</h1>
          <p>{ltiLaunchSubtitle({ mode })}</p>
        </header>
        <BulkIssuanceSection view={input.bulkIssuanceView} />
        <CourseBadgeSummarySection view={input.courseBadgeSummaryView} />
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
        <input type="hidden" name="lti_session_id" value={input.ltiSessionId} />
        <input type="hidden" name="badge_template_id" value={input.option.badgeTemplateId} />
        <LtiSubmitButton>Place Template in LMS</LtiSubmitButton>
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
              />
            ))
          )}
        </section>
      </section>
    ),
  });
};
