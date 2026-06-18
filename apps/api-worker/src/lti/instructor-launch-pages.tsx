import { formatIsoTimestamp } from "../utils/display-format";
import { LTI_ACTIVE_BADGE_SUMMARY_STATUS } from "./badge-summary-helpers";
import {
  BadgeSummaryContent,
  DetailRows,
  type HonoElement,
  LtiLaunchCard,
  LtiSubmitButton,
} from "./launch-page-components";
import type {
  LtiBadgeSummaryCard,
  LtiBulkIssuanceRosterMember,
  LtiBulkIssuanceView,
  LtiCourseBadgeSummaryView,
} from "./view-models";

const SelectedBulkBadgeSection = (input: {
  badge: LtiBulkIssuanceView["selectedBadge"];
}): HonoElement => {
  return (
    <section
      class="lti-launch__badge-summary lti-launch__badge-summary--selected lti-launch__selected-badge"
      aria-labelledby="lti-selected-badge-title"
    >
      <BadgeSummaryContent
        badge={input.badge}
        heading="h3"
        headingId="lti-selected-badge-title"
        srOnlySuffix="criteria and qualification rules"
        status={LTI_ACTIVE_BADGE_SUMMARY_STATUS}
      />
    </section>
  );
};

export const BulkIssuanceSection = (input: {
  view: LtiBulkIssuanceView | null;
}): HonoElement | null => {
  if (input.view === null) {
    return null;
  }

  const view = input.view;
  const canIssue =
    view.status === "ready" &&
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
      <SelectedBulkBadgeSection badge={view.selectedBadge} />
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

const CourseBadgeOverviewSection = (input: {
  badges: readonly LtiBadgeSummaryCard[];
}): HonoElement | null => {
  if (input.badges.length === 0) {
    return null;
  }

  return (
    <section class="lti-launch__badge-overview" aria-labelledby="lti-course-badges-title">
      <header class="lti-launch__badge-overview-head">
        <h3 id="lti-course-badges-title">Badges in this course</h3>
        <p class="lti-launch__hint">Open a badge to review criteria and qualification rules.</p>
      </header>
      <ul class="lti-launch__badge-list">
        {input.badges.map((badge, index) => (
          <li
            class="lti-launch__badge-summary lti-launch__badge-summary--list"
            key={badge.badgeTemplateId}
          >
            <BadgeSummaryContent
              badge={badge}
              heading="h4"
              srOnlySuffix="criteria and rules"
              status={LTI_ACTIVE_BADGE_SUMMARY_STATUS}
              {...(index === 0 ? {} : { imageLoading: "lazy" as const })}
            />
          </li>
        ))}
      </ul>
    </section>
  );
};

export const CourseBadgeSummarySection = (input: {
  view: LtiCourseBadgeSummaryView | null;
}): HonoElement | null => {
  if (input.view === null) {
    return null;
  }

  const view = input.view;
  const badgeOptions = view.badges.map((badge) => ({
    badgeTemplateId: badge.badgeTemplateId,
    badgeTitle: badge.title,
  }));
  const hasRows = view.rows.length > 0;
  const hasPlacedBadges = view.badgeCount > 0;
  const showPlacementGuidance = !hasPlacedBadges && view.canPlaceBadgesFromLti;

  return (
    <LtiLaunchCard stack={true}>
      <div class="lti-launch__course-summary" data-lti-course-summary>
        <header class="lti-launch__section-head">
          <h2 class="lti-launch__bulk-title">Course badge summary</h2>
          <p class="lti-launch__hint">
            {hasRows
              ? "Search learners, badges, or status in this course."
              : hasPlacedBadges
                ? "Badge placements exist, but no learner badge rows are available yet."
                : showPlacementGuidance
                  ? "Place a CredTrail badge from your LMS content picker to start badging this course."
                  : "No badge placements are available for this LMS course yet."}
          </p>
        </header>
        <p class={`lti-launch__bulk-status lti-launch__bulk-status--${view.status}`}>
          {view.message}
        </p>
        <dl class="lti-launch__course-summary-stats">
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
                label: "Currently issued",
                value: view.issuedCount,
              },
            ]}
          />
        </dl>
        <CourseBadgeOverviewSection badges={view.badges} />
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
        {hasRows ? (
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
                          <a href={row.learnerDetailPath} target="_blank" rel="noopener noreferrer">
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
                        {row.badgeDetailPath === null ? (
                          row.badgeTitle
                        ) : (
                          <a href={row.badgeDetailPath} target="_blank" rel="noopener noreferrer">
                            {row.badgeTitle}
                            <span class="lti-launch__sr-only"> badge setup for this course</span>
                          </a>
                        )}
                      </td>
                      <td>
                        <div class="lti-launch__status-stack">
                          <span
                            class={`lti-launch__status-pill lti-launch__status-pill--${row.status}`}
                          >
                            {row.statusLabel}
                          </span>
                          {row.issuedAt === null ? null : (
                            <time class="lti-launch__summary-timestamp" dateTime={row.issuedAt}>
                              Issued {formatIsoTimestamp(row.issuedAt)} UTC
                            </time>
                          )}
                          <span class="lti-launch__summary-status-detail">{row.statusDetail}</span>
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
              </tbody>
            </table>
          </div>
        ) : (
          <div class="lti-launch__course-summary-empty">
            <strong>
              {hasPlacedBadges ? "No learner badge rows yet" : "No badges placed yet"}
            </strong>
            <p>
              {hasPlacedBadges
                ? "CredTrail could not build learner badge rows for this course. Try again after roster and badge data are available."
                : showPlacementGuidance
                  ? "Use the LMS add-content or external-tool flow, choose CredTrail, then select a badge template. After the badge is placed, launch it from this course to issue it from the roster."
                  : "Once a badge is placed in this course, instructors will see learner badge status here."}
            </p>
          </div>
        )}
      </div>
    </LtiLaunchCard>
  );
};
