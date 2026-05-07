import type { LtiIssuerRegistrationRecord, TenantMembershipRole } from "@credtrail/db";
import type { LtiRoleKind } from "@credtrail/lti";
import { renderPageShell } from "@credtrail/ui-components";
import { renderPageAssetTags } from "../ui/page-assets";

const escapeHtml = (value: string): string => {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
};

const ltiRoleLabel = (roleKind: LtiRoleKind): string => {
  if (roleKind === "instructor") {
    return "Instructor";
  }

  if (roleKind === "learner") {
    return "Learner";
  }

  return "Unknown role";
};

const LTI_PAGE_HEAD_TAGS = renderPageAssetTags(["foundationCss", "ltiPagesCss"]);

export const ltiPostMessageStorageRedirectPage = (input: {
  authorizationRedirectUrl: string;
  platformOrigin: string;
  storageTarget: string;
  state: string;
  nonce: string;
}): string => {
  return renderPageShell(
    "LTI Launch Redirect | CredTrail",
    `<section class="lti-launch">
      <header class="lti-launch__hero">
        <h1>Continuing LTI launch</h1>
      </header>
    </section>
    <script>
      (() => {
        const authorizationRedirectUrl = ${JSON.stringify(input.authorizationRedirectUrl)};
        const platformOrigin = ${JSON.stringify(input.platformOrigin)};
        const storageTarget = ${JSON.stringify(input.storageTarget)};
        const entries = [
          {
            key: ${JSON.stringify(`state_${input.state}`)},
            value: ${JSON.stringify(input.state)}
          },
          {
            key: ${JSON.stringify(`nonce_${input.nonce}`)},
            value: ${JSON.stringify(input.nonce)}
          }
        ];

        const redirect = () => {
          window.location.replace(authorizationRedirectUrl);
        };

        const parentWindow = window.parent !== window ? window.parent : window.opener;
        if (!parentWindow) {
          redirect();
          return;
        }

        const targetFrame =
          storageTarget === "_parent" ? parentWindow : parentWindow.frames[storageTarget];

        if (!targetFrame) {
          redirect();
          return;
        }

        const postToStorageFrame = (message) => {
          targetFrame.postMessage(JSON.stringify(message), platformOrigin);
        };
        const pending = new Set(entries.map((entry) => entry.key));
        const createMessageId = () => {
          if (crypto.randomUUID) {
            return crypto.randomUUID();
          }

          return \`credtrail-lti-\${Date.now()}-\${Math.random().toString(16).slice(2)}\`;
        };
        const messageIds = new Map(entries.map((entry) => [createMessageId(), entry.key]));
        const timeout = window.setTimeout(redirect, 1500);
        let storageMessagesPosted = false;

        const postStorageMessages = () => {
          if (storageMessagesPosted) {
            return;
          }

          storageMessagesPosted = true;

          for (const [messageId, key] of messageIds.entries()) {
            const entry = entries.find((candidate) => candidate.key === key);
            if (entry === undefined) {
              continue;
            }

            postToStorageFrame({
              subject: "lti.put_data",
              message_id: messageId,
              key: entry.key,
              value: entry.value
            });
          }
        };

        window.addEventListener("message", (event) => {
          if (event.origin !== platformOrigin) {
            return;
          }

          let message = event.data;
          if (typeof message === "string") {
            try {
              message = JSON.parse(message);
            } catch {
              return;
            }
          }

          if (typeof message !== "object" || message === null) {
            return;
          }

          if (message.subject === "org.sakailms.lti.prelaunch.response") {
            postStorageMessages();
            return;
          }

          if (message.subject !== "lti.put_data.response") {
            return;
          }

          const key = messageIds.get(message.message_id);
          if (key === undefined) {
            return;
          }

          if (message.error === undefined) {
            pending.delete(key);
          }

          if (pending.size === 0) {
            window.clearTimeout(timeout);
            redirect();
          }
        });

        postToStorageFrame({ subject: "org.sakailms.lti.prelaunch" });
        window.setTimeout(postStorageMessages, 250);
      })();
    </script>`,
    LTI_PAGE_HEAD_TAGS,
  );
};

export interface LtiBulkIssuanceRosterMember {
  userId: string;
  sourcedId: string | null;
  displayName: string | null;
  email: string | null;
  roleSummary: string;
  status: string | null;
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
  members: readonly LtiBulkIssuanceRosterMember[];
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
  bulkIssuanceView: LtiBulkIssuanceView | null;
}): string => {
  const bulkIssuanceSection =
    input.bulkIssuanceView === null
      ? ""
      : (() => {
          const view = input.bulkIssuanceView;
          const rosterRows =
            view.members.length === 0
              ? '<tr><td colspan="5" class="lti-launch__bulk-empty">No learner members returned by LMS roster for this launch.</td></tr>'
              : view.members
                  .map((member) => {
                    const displayName = member.displayName ?? member.userId;
                    const email = member.email ?? "Not provided";
                    const sourcedId = member.sourcedId ?? "Not provided";
                    const roles =
                      member.roleSummary.length === 0 ? "Not provided" : member.roleSummary;
                    const status = member.status ?? "Not provided";

                    return `<tr>
              <td>${escapeHtml(displayName)}</td>
              <td>${escapeHtml(email)}</td>
              <td>${escapeHtml(sourcedId)}</td>
              <td>${escapeHtml(roles)}</td>
              <td>${escapeHtml(status)}</td>
            </tr>`;
                  })
                  .join("\n");
          const contextTitle =
            view.courseContextTitle === null ? "Not provided" : escapeHtml(view.courseContextTitle);
          const contextId =
            view.courseContextId === null ? "Not provided" : escapeHtml(view.courseContextId);
          const badgeTemplateId =
            view.badgeTemplateId === null
              ? "Not provided in placement URL"
              : escapeHtml(view.badgeTemplateId);
          const contextMembershipsUrl =
            view.contextMembershipsUrl === null
              ? "Not provided"
              : escapeHtml(view.contextMembershipsUrl);

          return `<article class="lti-launch__card lti-launch__card--stack">
        <h2 class="lti-launch__bulk-title">Bulk issuance view</h2>
        <p class="lti-launch__hint">NRPS roster pull for instructor launch context.</p>
        <p class="lti-launch__bulk-status lti-launch__bulk-status--${escapeHtml(view.status)}">${escapeHtml(
          view.message,
        )}</p>
        <dl class="lti-launch__bulk-meta">
          <dt>Badge template</dt>
          <dd>${badgeTemplateId}</dd>
          <dt>Course context</dt>
          <dd>${contextTitle}</dd>
          <dt>Course context ID</dt>
          <dd>${contextId}</dd>
          <dt>Roster endpoint</dt>
          <dd>${contextMembershipsUrl}</dd>
          <dt>Learner members</dt>
          <dd>${escapeHtml(String(view.learnerCount))} of ${escapeHtml(String(view.totalCount))}</dd>
        </dl>
        <div class="lti-launch__bulk-table-wrap">
          <table class="lti-launch__bulk-table">
            <thead>
              <tr>
                <th>Learner</th>
                <th>Email</th>
                <th>Sourced ID</th>
                <th>Roles</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${rosterRows}
            </tbody>
          </table>
        </div>
      </article>`;
        })();

  return renderPageShell(
    "LTI Launch Complete | CredTrail",
    `<section class="lti-launch">
      <header class="lti-launch__hero">
        <h1>LTI 1.3 launch complete</h1>
        <p>Launch accepted for <strong>${escapeHtml(ltiRoleLabel(input.roleKind))}</strong>.</p>
      </header>
      <article class="lti-launch__card">
        <dl class="lti-launch__details">
          <dt>Issuer</dt>
          <dd>${escapeHtml(input.issuer)}</dd>
          <dt>Deployment ID</dt>
          <dd>${escapeHtml(input.deploymentId)}</dd>
          <dt>Tenant</dt>
          <dd>${escapeHtml(input.tenantId)}</dd>
          <dt>User ID</dt>
          <dd>${escapeHtml(input.userId)}</dd>
          <dt>Membership role</dt>
          <dd>${escapeHtml(input.membershipRole)}</dd>
          <dt>Learner profile</dt>
          <dd>${escapeHtml(input.learnerProfileId)}</dd>
          <dt>LTI subject</dt>
          <dd>${escapeHtml(input.subjectId)}</dd>
          <dt>Message type</dt>
          <dd>${escapeHtml(input.messageType)}</dd>
          <dt>Target link URI</dt>
          <dd>${escapeHtml(input.targetLinkUri)}</dd>
        </dl>
      </article>
      <article class="lti-launch__card lti-launch__card--stack">
        <p class="lti-launch__hint">LTI identity is linked and this browser is now signed into CredTrail.</p>
        <p class="lti-launch__link-row">
          <a href="${escapeHtml(input.dashboardPath)}" target="_blank" rel="noopener noreferrer">Open learner dashboard</a>
        </p>
      </article>
      ${bulkIssuanceSection}
    </section>`,
    LTI_PAGE_HEAD_TAGS,
  );
};

export const ltiDeepLinkSelectionPage = (input: LtiDeepLinkSelectionPageInput): string => {
  const renderOption = (option: LtiDeepLinkSelectionOption, form: string): string => {
    const description =
      option.description === null
        ? '<p class="lti-deep-link__description">No template description provided.</p>'
        : `<p class="lti-deep-link__description">${escapeHtml(option.description)}</p>`;

    return `<article class="lti-deep-link__option">
              <h2>${escapeHtml(option.title)}</h2>
              <p class="lti-deep-link__meta">Template ID: ${escapeHtml(option.badgeTemplateId)}</p>
              ${description}
              <p class="lti-deep-link__meta">
                Launch URL:
                <a href="${escapeHtml(option.launchUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(option.launchUrl)}</a>
              </p>
              ${form}
            </article>`;
  };

  const optionRows =
    input.options.length === 0
      ? '<p class="lti-deep-link__empty">No active badge templates are available for this tenant.</p>'
      : input.options
          .map((option) =>
            renderOption(
              option,
              `<form method="post" action="${escapeHtml(input.signedSelectionActionUrl)}" class="lti-deep-link__form">
                <input type="hidden" name="lti_session_id" value="${escapeHtml(input.ltiSessionId)}" />
                <input type="hidden" name="badge_template_id" value="${escapeHtml(option.badgeTemplateId)}" />
                <button type="submit">Place Template in LMS</button>
              </form>`,
            ),
          )
          .join("\n");

  return renderPageShell(
    "LTI Deep Linking | CredTrail",
    `<section class="lti-deep-link">
      <header class="lti-deep-link__hero">
        <h1>Select badge template placement</h1>
        <p>Choose a badge template and return it to your LMS via LTI Deep Linking.</p>
      </header>
      <article class="lti-deep-link__details-card">
        <dl class="lti-deep-link__details">
          <dt>Issuer</dt>
          <dd>${escapeHtml(input.issuer)}</dd>
          <dt>Deployment ID</dt>
          <dd>${escapeHtml(input.deploymentId)}</dd>
          <dt>Tenant</dt>
          <dd>${escapeHtml(input.tenantId)}</dd>
          <dt>User ID</dt>
          <dd>${escapeHtml(input.userId)}</dd>
          <dt>Membership role</dt>
          <dd>${escapeHtml(input.membershipRole)}</dd>
          <dt>Deep link return URL</dt>
          <dd>${escapeHtml(input.deepLinkReturnUrl)}</dd>
          <dt>Target link URI</dt>
          <dd>${escapeHtml(input.targetLinkUri)}</dd>
        </dl>
      </article>
      <section class="lti-deep-link__options">
        ${optionRows}
      </section>
    </section>`,
    LTI_PAGE_HEAD_TAGS,
  );
};

export interface LtiIssuerRegistrationFormState {
  issuer?: string;
  tenantId?: string;
  authorizationEndpoint?: string;
  clientId?: string;
  platformJwksEndpoint?: string;
  tokenEndpoint?: string;
}

export const ltiIssuerRegistrationAdminPage = (input: {
  token: string;
  registrations: readonly LtiIssuerRegistrationRecord[];
  submissionError?: string;
  formState?: LtiIssuerRegistrationFormState;
}): string => {
  const registrationRows =
    input.registrations.length === 0
      ? '<tr><td colspan="7" class="lti-registration__empty">No LTI issuer registrations configured.</td></tr>'
      : input.registrations
          .map((registration) => {
            const tokenEndpointCell =
              registration.tokenEndpoint === null
                ? "Not configured"
                : escapeHtml(registration.tokenEndpoint);
            const jwksEndpointCell =
              registration.platformJwksEndpoint === null
                ? "Not configured"
                : escapeHtml(registration.platformJwksEndpoint);

            return `<tr>
      <td class="lti-registration__wrap-anywhere">${escapeHtml(registration.issuer)}</td>
      <td>${escapeHtml(registration.tenantId)}</td>
      <td class="lti-registration__wrap-anywhere">${escapeHtml(registration.clientId)}</td>
      <td class="lti-registration__wrap-anywhere">${escapeHtml(registration.authorizationEndpoint)}</td>
      <td class="lti-registration__wrap-anywhere">${jwksEndpointCell}</td>
      <td class="lti-registration__wrap-anywhere">${tokenEndpointCell}</td>
      <td>
        <form method="post" action="/admin/lti/issuer-registrations/delete">
          <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
          <input type="hidden" name="issuer" value="${escapeHtml(registration.issuer)}" />
          <button type="submit">Delete</button>
        </form>
      </td>
    </tr>`;
          })
          .join("\n");

  return renderPageShell(
    "LTI Issuer Registrations | CredTrail",
    `<section class="lti-registration">
      <h1 class="lti-registration__title">Manual LTI issuer registration configuration</h1>
      <p class="lti-registration__lede">
        Configure issuer mappings used by LTI 1.3 OIDC login and launch. Stored registrations override env-based defaults.
      </p>
      ${
        input.submissionError === undefined
          ? ""
          : `<p class="lti-registration__error">
              ${escapeHtml(input.submissionError)}
            </p>`
      }
      <form method="post" action="/admin/lti/issuer-registrations" class="lti-registration__form">
        <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
        <label class="lti-registration__field">
          <span>Issuer URL</span>
          <input name="issuer" type="url" required value="${escapeHtml(input.formState?.issuer ?? "")}" />
        </label>
        <label class="lti-registration__field">
          <span>Tenant ID</span>
          <input name="tenantId" type="text" required value="${escapeHtml(input.formState?.tenantId ?? "")}" />
        </label>
        <label class="lti-registration__field">
          <span>Client ID</span>
          <input name="clientId" type="text" required value="${escapeHtml(input.formState?.clientId ?? "")}" />
        </label>
        <label class="lti-registration__field">
          <span>Authorization endpoint</span>
          <input name="authorizationEndpoint" type="url" required value="${escapeHtml(input.formState?.authorizationEndpoint ?? "")}" />
        </label>
        <label class="lti-registration__field">
          <span>Platform JWKS endpoint</span>
          <input name="platformJwksEndpoint" type="url" value="${escapeHtml(input.formState?.platformJwksEndpoint ?? "")}" />
        </label>
        <label class="lti-registration__field">
          <span>Token endpoint</span>
          <input name="tokenEndpoint" type="url" value="${escapeHtml(input.formState?.tokenEndpoint ?? "")}" />
        </label>
        <div class="lti-registration__actions">
          <button type="submit">Save registration</button>
        </div>
      </form>
      <div class="lti-registration__table-wrap">
        <table class="lti-registration__table">
          <thead>
            <tr>
              <th>Issuer</th>
              <th>Tenant</th>
              <th>Client ID</th>
              <th>Authorization endpoint</th>
              <th>Platform JWKS endpoint</th>
              <th>Token endpoint</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${registrationRows}
          </tbody>
        </table>
      </div>
    </section>`,
    LTI_PAGE_HEAD_TAGS,
  );
};
