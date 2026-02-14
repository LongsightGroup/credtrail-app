import type { LtiIssuerRegistrationRecord, TenantMembershipRole } from '@credtrail/db';
import type { LtiRoleKind } from '@credtrail/lti';
import { renderPageShell } from '@credtrail/ui-components';

const escapeHtml = (value: string): string => {
  return value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
};

const ltiRoleLabel = (roleKind: LtiRoleKind): string => {
  if (roleKind === 'instructor') {
    return 'Instructor';
  }

  if (roleKind === 'learner') {
    return 'Learner';
  }

  return 'Unknown role';
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
  dashboardPath: string;
}): string => {
  return renderPageShell(
    'LTI Launch Complete | CredTrail',
    `<section style="display:grid;gap:1rem;max-width:52rem;">
      <h1 style="margin:0;">LTI 1.3 launch complete</h1>
      <p style="margin:0;color:#334155;">
        Launch accepted for <strong>${escapeHtml(ltiRoleLabel(input.roleKind))}</strong>.
      </p>
      <dl style="margin:0;display:grid;grid-template-columns:minmax(12rem,max-content) 1fr;gap:0.45rem 0.8rem;">
        <dt style="font-weight:600;">Issuer</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.issuer)}</dd>
        <dt style="font-weight:600;">Deployment ID</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.deploymentId)}</dd>
        <dt style="font-weight:600;">Tenant</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.tenantId)}</dd>
        <dt style="font-weight:600;">User ID</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.userId)}</dd>
        <dt style="font-weight:600;">Membership role</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.membershipRole)}</dd>
        <dt style="font-weight:600;">Learner profile</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.learnerProfileId)}</dd>
        <dt style="font-weight:600;">LTI subject</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.subjectId)}</dd>
        <dt style="font-weight:600;">Message type</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.messageType)}</dd>
        <dt style="font-weight:600;">Target link URI</dt>
        <dd style="margin:0;overflow-wrap:anywhere;">${escapeHtml(input.targetLinkUri)}</dd>
      </dl>
      <p style="margin:0;color:#475569;">
        LTI identity is linked and this browser is now signed into CredTrail.
      </p>
      <p style="margin:0;">
        <a href="${escapeHtml(input.dashboardPath)}">Open learner dashboard</a>
      </p>
    </section>`,
  );
};

export interface LtiIssuerRegistrationFormState {
  issuer?: string;
  tenantId?: string;
  authorizationEndpoint?: string;
  clientId?: string;
  allowUnsignedIdToken?: boolean;
}

export const ltiIssuerRegistrationAdminPage = (input: {
  token: string;
  registrations: readonly LtiIssuerRegistrationRecord[];
  submissionError?: string;
  formState?: LtiIssuerRegistrationFormState;
}): string => {
  const registrationRows =
    input.registrations.length === 0
      ? '<tr><td colspan="6" style="padding:0.75rem;">No LTI issuer registrations configured.</td></tr>'
      : input.registrations
          .map((registration) => {
            return `<tr>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.issuer)}</td>
      <td style="padding:0.5rem;vertical-align:top;">${escapeHtml(registration.tenantId)}</td>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.clientId)}</td>
      <td style="padding:0.5rem;vertical-align:top;word-break:break-word;">${escapeHtml(registration.authorizationEndpoint)}</td>
      <td style="padding:0.5rem;vertical-align:top;">${registration.allowUnsignedIdToken ? 'true' : 'false'}</td>
      <td style="padding:0.5rem;vertical-align:top;">
        <form method="post" action="/admin/lti/issuer-registrations/delete">
          <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
          <input type="hidden" name="issuer" value="${escapeHtml(registration.issuer)}" />
          <button type="submit">Delete</button>
        </form>
      </td>
    </tr>`;
          })
          .join('\n');

  return renderPageShell(
    'LTI Issuer Registrations | CredTrail',
    `<section style="display:grid;gap:1rem;max-width:64rem;">
      <h1 style="margin:0;">Manual LTI issuer registration configuration</h1>
      <p style="margin:0;color:#334155;">
        Configure issuer mappings used by LTI 1.3 OIDC login and launch. Stored registrations override env-based defaults.
      </p>
      ${
        input.submissionError === undefined
          ? ''
          : `<p style="margin:0;padding:0.75rem;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;">
              ${escapeHtml(input.submissionError)}
            </p>`
      }
      <form method="post" action="/admin/lti/issuer-registrations" style="display:grid;gap:0.75rem;padding:1rem;border:1px solid #cbd5e1;border-radius:0.5rem;">
        <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
        <label style="display:grid;gap:0.35rem;">
          <span>Issuer URL</span>
          <input name="issuer" type="url" required value="${escapeHtml(input.formState?.issuer ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Tenant ID</span>
          <input name="tenantId" type="text" required value="${escapeHtml(input.formState?.tenantId ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Client ID</span>
          <input name="clientId" type="text" required value="${escapeHtml(input.formState?.clientId ?? '')}" />
        </label>
        <label style="display:grid;gap:0.35rem;">
          <span>Authorization endpoint</span>
          <input name="authorizationEndpoint" type="url" required value="${escapeHtml(input.formState?.authorizationEndpoint ?? '')}" />
        </label>
        <label style="display:flex;gap:0.5rem;align-items:center;">
          <input name="allowUnsignedIdToken" type="checkbox" ${
            input.formState?.allowUnsignedIdToken === true ? 'checked' : ''
          } />
          <span>Allow unsigned id_token (test-mode only)</span>
        </label>
        <div>
          <button type="submit">Save registration</button>
        </div>
      </form>
      <div style="overflow:auto;">
        <table style="width:100%;border-collapse:collapse;">
          <thead>
            <tr>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Issuer</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Tenant</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Client ID</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Authorization endpoint</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Unsigned test mode</th>
              <th style="text-align:left;padding:0.5rem;border-bottom:1px solid #cbd5e1;">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${registrationRows}
          </tbody>
        </table>
      </div>
    </section>`,
  );
};
