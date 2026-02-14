import type { LearnerBadgeSummaryRecord } from '@credtrail/db';
import { renderPageShell } from '@credtrail/ui-components';

export type LearnerDidSettingsNotice = 'updated' | 'cleared' | 'conflict' | 'invalid';

export const learnerDidSettingsNoticeFromQuery = (
  value: string | undefined,
): LearnerDidSettingsNotice | null => {
  switch (value) {
    case 'updated':
    case 'cleared':
    case 'conflict':
    case 'invalid':
      return value;
    default:
      return null;
  }
};

interface CreateLearnerDashboardPageInput {
  escapeHtml: (value: string) => string;
  formatIsoTimestamp: (timestampIso: string) => string;
}

export const createLearnerDashboardPage = (input: CreateLearnerDashboardPageInput) => {
  const { escapeHtml, formatIsoTimestamp } = input;

  return (
    requestUrl: string,
    tenantId: string,
    badges: readonly LearnerBadgeSummaryRecord[],
    learnerDid: string | null,
    didNotice: LearnerDidSettingsNotice | null,
  ): string => {
    const didNoticeMarkup =
      didNotice === null
        ? ''
        : didNotice === 'updated'
          ? '<p style="margin:0;color:#166534;font-weight:600;">Learner DID updated. Newly issued badges will use this DID as credentialSubject.id.</p>'
          : didNotice === 'cleared'
            ? '<p style="margin:0;color:#334155;font-weight:600;">Learner DID cleared. Badge issuance will fall back to the default learner subject identifier.</p>'
            : didNotice === 'conflict'
              ? '<p style="margin:0;color:#a32020;font-weight:600;">That DID is already linked to another learner profile in this tenant.</p>'
              : '<p style="margin:0;color:#a32020;font-weight:600;">DID must use one of the supported methods: did:key, did:web, or did:ion.</p>';
    const didValue = learnerDid ?? '';
    const didSummaryMarkup =
      learnerDid === null
        ? '<p style="margin:0;color:#475569;">No learner DID is currently configured.</p>'
        : `<p style="margin:0;color:#0f172a;overflow-wrap:anywhere;">Current DID: <code>${escapeHtml(learnerDid)}</code></p>`;
    const didSettingsCard = `<article style="display:grid;gap:0.75rem;background:#ffffff;border:1px solid #d6dfeb;border-radius:1rem;padding:1rem;">
      <h2 style="margin:0;">Profile settings</h2>
      <p style="margin:0;color:#334155;">
        Set an optional learner DID to issue privacy-preserving badges directly to your wallet identifier.
        Supported methods: <code>did:key</code>, <code>did:web</code>, and <code>did:ion</code>.
      </p>
      ${didNoticeMarkup}
      ${didSummaryMarkup}
      <form method="post" action="/tenants/${encodeURIComponent(tenantId)}/learner/settings/did" style="display:grid;gap:0.6rem;">
        <label style="font-weight:600;display:grid;gap:0.3rem;">
          Learner DID
          <input
            name="did"
            type="text"
            value="${escapeHtml(didValue)}"
            placeholder="did:key:z6Mk..."
            style="padding:0.55rem 0.65rem;border:1px solid #cbd5e1;border-radius:0.5rem;"
          />
        </label>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          <button type="submit" style="padding:0.45rem 0.85rem;border-radius:0.5rem;border:1px solid #1d4ed8;background:#1d4ed8;color:#ffffff;font-weight:600;cursor:pointer;">Save DID</button>
          <button
            type="submit"
            name="did"
            value=""
            style="padding:0.45rem 0.85rem;border-radius:0.5rem;border:1px solid #94a3b8;background:#ffffff;color:#1e293b;font-weight:600;cursor:pointer;"
          >
            Clear DID
          </button>
        </div>
      </form>
    </article>`;

    const badgesMarkup =
      badges.length === 0
        ? '<p style="margin:0;">No badges have been issued to this learner account yet.</p>'
        : `<div style="display:grid;gap:0.9rem;">${badges
            .map((badge) => {
              const statusLabel = badge.revokedAt === null ? 'Verified' : 'Revoked';
              const statusVariant = badge.revokedAt === null ? 'success' : 'danger';
              const publicBadgeId = badge.assertionPublicId ?? badge.assertionId;
              const publicBadgePath = `/badges/${encodeURIComponent(publicBadgeId)}`;
              const publicBadgeUrl = new URL(publicBadgePath, requestUrl).toString();
              const descriptionMarkup =
                badge.badgeDescription === null
                  ? ''
                  : `<p style="margin:0;color:#3d4b66;">${escapeHtml(badge.badgeDescription)}</p>`;
              const revokedAtMarkup =
                badge.revokedAt === null
                  ? ''
                  : `<p style="margin:0;color:#a32020;">Revoked at ${escapeHtml(formatIsoTimestamp(badge.revokedAt))} UTC</p>`;

              return `<article style="display:grid;gap:0.75rem;background:#ffffff;border:1px solid #d6dfeb;border-radius:1rem;padding:1rem;">
                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:center;flex-wrap:wrap;">
                  <h3 style="margin:0;">${escapeHtml(badge.badgeTitle)}</h3>
                  <sl-badge variant="${statusVariant}" pill>${statusLabel}</sl-badge>
                </div>
                ${descriptionMarkup}
                <p style="margin:0;">Issued at ${escapeHtml(formatIsoTimestamp(badge.issuedAt))} UTC</p>
                ${revokedAtMarkup}
                <p style="margin:0;">
                  Public badge page:
                  <a href="${escapeHtml(publicBadgePath)}">${escapeHtml(publicBadgeUrl)}</a>
                </p>
              </article>`;
            })
            .join('')}</div>`;

    return renderPageShell(
      'Learner dashboard | CredTrail',
      `<section style="display:grid;gap:1rem;max-width:56rem;">
        <h1 style="margin:0;">Your badges</h1>
        <p style="margin:0;color:#3d4b66;">Tenant: ${escapeHtml(tenantId)}</p>
        ${didSettingsCard}
        ${badgesMarkup}
      </section>`,
    );
  };
};
