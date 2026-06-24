import type { LearnerBadgeSummaryRecord } from "@credtrail/db";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtActionGroup, CtButton } from "../ui/actions";
import { appPage, type AppPage } from "../ui/render-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

export type LearnerDidSettingsNotice = "updated" | "cleared" | "conflict" | "invalid";
export type LearnerClaimStatusNotice = "recorded" | "already_recorded" | "invalid";
export type LearnerBadgeClaimState = "claimable" | "claimed" | "accepted";

export interface LearnerDashboardBadge extends LearnerBadgeSummaryRecord {
  claimState: LearnerBadgeClaimState;
}

const LearnerButtonRow = ({ children }: PropsWithChildren): HonoElement => {
  return <CtActionGroup className="learner-dashboard__button-row">{children}</CtActionGroup>;
};

export const learnerDidSettingsNoticeFromQuery = (
  value: string | undefined,
): LearnerDidSettingsNotice | null => {
  switch (value) {
    case "updated":
    case "cleared":
    case "conflict":
    case "invalid":
      return value;
    default:
      return null;
  }
};

const normalizeLearnerClaimStatusNotice = (
  value: string | null,
): LearnerClaimStatusNotice | null => {
  switch (value) {
    case "recorded":
    case "already_recorded":
    case "invalid":
      return value;
    default:
      return null;
  }
};

interface CreateLearnerDashboardPageInput {
  formatIsoTimestamp: (timestampIso: string) => string;
}

const learnerDashboardAppPage = (body: HonoElement): AppPage => {
  return appPage({
    title: "Learner dashboard | CredTrail",
    body,
    assets: ["learnerDashboardCss"],
    variant: "open",
  });
};

const DidNotice = (input: { notice: LearnerDidSettingsNotice | null }): HonoElement | null => {
  switch (input.notice) {
    case "updated":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--success">
          Learner DID updated. Newly issued badges will use this DID as credentialSubject.id.
        </p>
      );
    case "cleared":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--info">
          Learner DID cleared. Badge issuance will fall back to the default learner subject
          identifier.
        </p>
      );
    case "conflict":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--danger">
          That DID is already linked to another learner profile in this tenant.
        </p>
      );
    case "invalid":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--danger">
          DID must use one of the supported methods: did:key, did:web, or did:ion.
        </p>
      );
    case null:
      return null;
  }
};

const ClaimNotice = (input: { notice: LearnerClaimStatusNotice | null }): HonoElement | null => {
  switch (input.notice) {
    case "recorded":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--success">
          Credential claim recorded from your dashboard.
        </p>
      );
    case "already_recorded":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--info">
          This credential was already claimed from your dashboard.
        </p>
      );
    case "invalid":
      return (
        <p class="learner-dashboard__notice learner-dashboard__notice--danger">
          That badge could not be claimed from this dashboard.
        </p>
      );
    case null:
      return null;
  }
};

const LearnerDidSettings = (input: {
  tenantId: string;
  learnerDid: string | null;
  didNotice: LearnerDidSettingsNotice | null;
}): HonoElement => {
  const didSummaryText =
    input.learnerDid === null
      ? "No learner DID is currently configured."
      : "A learner DID is configured for future badge issuance.";
  const didSummaryPillClass =
    input.learnerDid === null
      ? "learner-dashboard__summary-pill"
      : "learner-dashboard__summary-pill learner-dashboard__summary-pill--configured";

  return (
    <section class="learner-dashboard__profile" aria-labelledby="learner-profile-settings">
      <div class="learner-dashboard__section-heading learner-dashboard__section-heading--compact">
        <div>
          <p class="learner-dashboard__eyebrow learner-dashboard__eyebrow--section">
            Profile settings
          </p>
          <h2 id="learner-profile-settings">Learner DID and privacy</h2>
          <p class="learner-dashboard__section-copy">
            Add an optional learner DID when you want new credentials issued directly to a
            wallet-friendly identifier.
          </p>
        </div>
      </div>
      <details class="learner-dashboard__profile-details" open={input.didNotice !== null}>
        <summary class="learner-dashboard__details-summary">
          <span class="learner-dashboard__details-copy">
            <span class="learner-dashboard__details-title">Manage learner DID</span>
            <span class="learner-dashboard__details-subtitle">{didSummaryText}</span>
          </span>
          <span class={didSummaryPillClass}>
            {input.learnerDid === null ? "Optional" : "Configured"}
          </span>
        </summary>
        <div class="learner-dashboard__details-panel">
          <DidNotice notice={input.didNotice} />
          {input.learnerDid === null ? (
            <p class="learner-dashboard__subtle">No learner DID is currently configured.</p>
          ) : (
            <p class="learner-dashboard__subtle learner-dashboard__subtle--break">
              Current DID: <code>{input.learnerDid}</code>
            </p>
          )}
          <p class="learner-dashboard__subtle">
            Supported methods: <code>did:key</code>, <code>did:web</code>, and <code>did:ion</code>.
          </p>
          <form
            method="post"
            action={`/tenants/${encodeURIComponent(input.tenantId)}/learner/settings/did`}
            class="learner-dashboard__did-form"
          >
            <label class="learner-dashboard__did-label">
              Learner DID
              <input
                name="did"
                type="text"
                value={input.learnerDid ?? ""}
                placeholder="did:key:z6Mk..."
                class="learner-dashboard__did-input"
              />
            </label>
            <LearnerButtonRow>
              <CtButton
                type="submit"
                variant="primary"
                size="lg"
                className="learner-dashboard__button"
              >
                Save DID
              </CtButton>
              <CtButton
                type="submit"
                name="did"
                value=""
                variant="quiet"
                size="lg"
                className="learner-dashboard__button"
              >
                Clear DID
              </CtButton>
            </LearnerButtonRow>
          </form>
        </div>
      </details>
    </section>
  );
};

const EmptyBadgeCollection = (): HonoElement => {
  return (
    <section class="learner-dashboard__collection" aria-labelledby="learner-badges">
      <div class="learner-dashboard__section-heading">
        <div>
          <p class="learner-dashboard__eyebrow learner-dashboard__eyebrow--section">
            Issued credentials
          </p>
          <h2 id="learner-badges">Your badges</h2>
          <p class="learner-dashboard__section-copy">
            Earned credentials will appear here with an official public badge page ready to share
            and verify.
          </p>
        </div>
      </div>
      <div class="learner-dashboard__empty-state">
        <p class="learner-dashboard__subtle">
          No badges have been issued to this learner account yet.
        </p>
        <p class="learner-dashboard__subtle">
          When a credential is published, it will show up here with its verification page for
          employers and reviewers.
        </p>
      </div>
    </section>
  );
};

const BadgeCard = (input: {
  tenantId: string;
  requestUrl: string;
  badge: LearnerDashboardBadge;
  formatIsoTimestamp: (timestampIso: string) => string;
}): HonoElement => {
  const statusLabel = input.badge.revokedAt === null ? "Verified" : "Revoked";
  const statusClass =
    input.badge.revokedAt === null
      ? "learner-dashboard__badge-status learner-dashboard__badge-status--verified"
      : "learner-dashboard__badge-status learner-dashboard__badge-status--revoked";
  const badgeCardClass =
    input.badge.revokedAt === null
      ? "learner-dashboard__badge-card learner-dashboard__badge-card--verified"
      : "learner-dashboard__badge-card learner-dashboard__badge-card--revoked";
  const badgeEyebrow = input.badge.revokedAt === null ? "Earned credential" : "Credential history";
  const publicBadgeId = input.badge.assertionPublicId ?? input.badge.assertionId;
  const publicBadgePath = `/badges/${encodeURIComponent(publicBadgeId)}`;
  const publicBadgeUrl = new URL(publicBadgePath, input.requestUrl).toString();

  return (
    <article class={badgeCardClass}>
      <div class="learner-dashboard__badge-topline">
        <span class="learner-dashboard__badge-eyebrow">{badgeEyebrow}</span>
        <span class={statusClass}>{statusLabel}</span>
      </div>
      <h3>{input.badge.badgeTitle}</h3>
      {input.badge.badgeDescription === null ? null : (
        <p class="learner-dashboard__badge-description">{input.badge.badgeDescription}</p>
      )}
      <div class="learner-dashboard__badge-meta">
        <div>
          <p class="learner-dashboard__meta-label">Issued</p>
          <p class="learner-dashboard__meta-value">
            {input.formatIsoTimestamp(input.badge.issuedAt)} UTC
          </p>
        </div>
        <div>
          <p class="learner-dashboard__meta-label">Verification page</p>
          <a class="learner-dashboard__badge-link" href={publicBadgePath}>
            View public badge
          </a>
        </div>
      </div>
      {input.badge.revokedAt === null ? null : (
        <p class="learner-dashboard__danger">
          Revoked at {input.formatIsoTimestamp(input.badge.revokedAt)} UTC
        </p>
      )}
      {input.badge.revokedAt !== null ? null : input.badge.claimState === "accepted" ? (
        <p class="learner-dashboard__claim-state learner-dashboard__claim-state--accepted">
          Accepted in wallet
        </p>
      ) : input.badge.claimState === "claimed" ? (
        <p class="learner-dashboard__claim-state learner-dashboard__claim-state--claimed">
          Claim recorded in CredTrail
        </p>
      ) : (
        <form
          method="post"
          action={`/tenants/${encodeURIComponent(input.tenantId)}/learner/badges/${encodeURIComponent(
            input.badge.assertionId,
          )}/claim`}
          class="learner-dashboard__claim-form"
        >
          <CtButton
            type="submit"
            variant="secondary"
            size="lg"
            className="learner-dashboard__button"
          >
            Claim badge and open sharing options
          </CtButton>
        </form>
      )}
      <p class="learner-dashboard__badge-url">{publicBadgeUrl}</p>
    </article>
  );
};

const BadgeCollection = (input: {
  tenantId: string;
  requestUrl: string;
  badges: readonly LearnerDashboardBadge[];
  formatIsoTimestamp: (timestampIso: string) => string;
}): HonoElement => {
  if (input.badges.length === 0) {
    return <EmptyBadgeCollection />;
  }

  return (
    <section class="learner-dashboard__collection" aria-labelledby="learner-badges">
      <div class="learner-dashboard__section-heading">
        <div>
          <p class="learner-dashboard__eyebrow learner-dashboard__eyebrow--section">
            Issued credentials
          </p>
          <h2 id="learner-badges">Your badges</h2>
          <p class="learner-dashboard__section-copy">
            Every badge below includes its official public page so hiring teams and reviewers can
            verify the credential directly.
          </p>
        </div>
      </div>
      <div class="learner-dashboard__badge-grid">
        {input.badges.map((badge) => (
          <BadgeCard
            key={badge.assertionId}
            tenantId={input.tenantId}
            requestUrl={input.requestUrl}
            badge={badge}
            formatIsoTimestamp={input.formatIsoTimestamp}
          />
        ))}
      </div>
    </section>
  );
};

export const createLearnerDashboardPage = (input: CreateLearnerDashboardPageInput) => {
  const { formatIsoTimestamp } = input;

  return (
    requestUrl: string,
    tenantId: string,
    badges: readonly LearnerDashboardBadge[],
    learnerDid: string | null,
    didNotice: LearnerDidSettingsNotice | null,
    claimNotice: string | null,
    switchOrganizationPath?: string | null,
    learnerRecordPath?: string | null,
  ): AppPage => {
    const normalizedClaimNotice = normalizeLearnerClaimStatusNotice(claimNotice);
    const totalBadges = badges.length;
    const activeBadges = badges.filter((badge) => badge.revokedAt === null).length;
    const revokedBadges = totalBadges - activeBadges;
    const totalBadgesLabel = String(totalBadges);
    const activeBadgesLabel = String(activeBadges);
    const revokedBadgesLabel = String(revokedBadges);
    const badgeCountLabel =
      totalBadges === 1 ? "1 recorded badge" : `${totalBadgesLabel} recorded badges`;
    const latestIssuedAt = badges.reduce<string | null>(
      (latest, badge) => (latest === null || badge.issuedAt > latest ? badge.issuedAt : latest),
      null,
    );
    const heroLead =
      totalBadges === 0
        ? "Your credential collection is ready for its first published badge."
        : activeBadges === totalBadges
          ? activeBadges === 1
            ? "1 verified badge is ready to share and verify."
            : `${activeBadgesLabel} verified badges are ready to share and verify.`
          : activeBadges > 0
            ? `${activeBadgesLabel} verified badge${activeBadges === 1 ? "" : "s"} remain ready to share, with ${revokedBadgesLabel} historical record${revokedBadges === 1 ? "" : "s"} preserved below.`
            : `${revokedBadgesLabel} revoked record${revokedBadges === 1 ? "" : "s"} remain visible in your collection history.`;
    const heroNote =
      totalBadges === 0
        ? "When a credential is issued to this learner account, it will appear here with its official public verification page."
        : "Each credential includes an official public page you can share with employers and reviewers for verification.";
    const switchPath = switchOrganizationPath?.trim();
    const recordPath = learnerRecordPath?.trim();

    return learnerDashboardAppPage(
      <section class="learner-dashboard">
        <header class="learner-dashboard__hero">
          <div>
            <p class="learner-dashboard__eyebrow">Learner dashboard</p>
            <h1>Your credential collection</h1>
            <p class="learner-dashboard__hero-lead">{heroLead}</p>
            <p class="learner-dashboard__hero-note">{heroNote}</p>
            <ul class="learner-dashboard__hero-chips">
              <li class="learner-dashboard__hero-chip">{badgeCountLabel}</li>
              <li class="learner-dashboard__hero-chip">Public verification ready</li>
              <li class="learner-dashboard__hero-chip">
                {learnerDid === null ? "Optional DID available" : "Learner DID configured"}
              </li>
            </ul>
            {recordPath === undefined || recordPath.length === 0 ? null : (
              <p class="learner-dashboard__hero-note learner-dashboard__hero-note--record">
                <a class="learner-dashboard__record-link" href={recordPath}>
                  Open full learner record
                </a>
              </p>
            )}
            {switchPath === undefined || switchPath.length === 0 ? null : (
              <p class="learner-dashboard__hero-note learner-dashboard__hero-note--switch">
                <a class="learner-dashboard__switch-link" href={switchPath}>
                  Switch organization
                </a>
              </p>
            )}
          </div>
          <div class="learner-dashboard__hero-card">
            <p class="learner-dashboard__hero-card-label">Tenant record</p>
            <p class="learner-dashboard__hero-card-value">{tenantId}</p>
            {latestIssuedAt === null ? (
              <p class="learner-dashboard__hero-card-note">Ready for the next published badge.</p>
            ) : (
              <p class="learner-dashboard__hero-card-note">
                Latest issue: <strong>{formatIsoTimestamp(latestIssuedAt)} UTC</strong>
              </p>
            )}
          </div>
        </header>
        <ClaimNotice notice={normalizedClaimNotice} />
        <BadgeCollection
          tenantId={tenantId}
          requestUrl={requestUrl}
          badges={badges}
          formatIsoTimestamp={formatIsoTimestamp}
        />
        <LearnerDidSettings tenantId={tenantId} learnerDid={learnerDid} didNotice={didNotice} />
      </section>,
    );
  };
};
