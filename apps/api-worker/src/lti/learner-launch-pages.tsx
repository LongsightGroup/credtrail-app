import { formatIsoTimestamp } from "../utils/display-format";
import { BadgeSummaryContent, type HonoElement, LtiLaunchCard } from "./launch-page-components";
import type { LtiLearnerBadgeSummaryView } from "./view-models";

export const LearnerBadgeSummarySection = (input: {
  view: LtiLearnerBadgeSummaryView | null;
  sessionHandoffToken?: string | null;
}): HonoElement | null => {
  if (input.view === null) {
    return null;
  }

  const view = input.view;
  const title = view.scope === "selected" ? "Selected badge" : "Badges in this course";
  const emptyTitle =
    view.scope === "selected" ? "No selected badge details" : "No badges placed yet";
  const claimActionPath = (path: string): string => {
    if (input.sessionHandoffToken === undefined || input.sessionHandoffToken === null) {
      return path;
    }

    const actionUrl = new URL(path, "https://credtrail.local");
    actionUrl.searchParams.set("lti_session_handoff", input.sessionHandoffToken);
    return `${actionUrl.pathname}${actionUrl.search}`;
  };

  return (
    <LtiLaunchCard stack={true}>
      <section class="lti-launch__learner-summary" aria-labelledby="lti-learner-badges-title">
        <header class="lti-launch__section-head">
          <h2 id="lti-learner-badges-title" class="lti-launch__bulk-title">
            {title}
          </h2>
          <p class={`lti-launch__bulk-status lti-launch__bulk-status--${view.status}`}>
            {view.message}
          </p>
        </header>
        {view.badges.length === 0 ? (
          <div class="lti-launch__course-summary-empty">
            <strong>{emptyTitle}</strong>
            <p>Open your CredTrail dashboard to review issued badges and sharing options.</p>
          </div>
        ) : (
          <ul class="lti-launch__badge-list lti-launch__learner-badge-list">
            {view.badges.map((item, index) => (
              <li
                class="lti-launch__badge-summary lti-launch__badge-summary--list lti-launch__learner-badge"
                key={item.badge.badgeTemplateId}
              >
                <BadgeSummaryContent
                  badge={item.badge}
                  heading="h3"
                  srOnlySuffix="criteria and earning requirements"
                  status={item.status}
                  {...(index === 0 ? {} : { imageLoading: "lazy" as const })}
                  footer={
                    <div class="lti-launch__learner-badge-footer">
                      {item.issuedAt === null ? (
                        <span class="lti-launch__summary-status-detail">Not issued yet.</span>
                      ) : (
                        <time class="lti-launch__summary-timestamp" dateTime={item.issuedAt}>
                          Issued {formatIsoTimestamp(item.issuedAt)} UTC
                        </time>
                      )}
                      {item.claimActionPath === null ? null : (
                        <form
                          method="post"
                          action={claimActionPath(item.claimActionPath)}
                          class="lti-launch__claim-form"
                        >
                          <button type="submit" class="lti-launch__claim-button">
                            Claim badge and open sharing options
                          </button>
                        </form>
                      )}
                    </div>
                  }
                />
              </li>
            ))}
          </ul>
        )}
      </section>
    </LtiLaunchCard>
  );
};
