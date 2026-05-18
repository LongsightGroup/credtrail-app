import type { LtiIssuerRegistrationRecord, TenantMembershipRole } from "@credtrail/db";
import type { LtiRoleKind } from "@credtrail/lti";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { appPage, type AppPage } from "../ui/render-page";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

const ltiPage = (input: {
  title: string;
  body: HonoElement;
  scripts?: readonly ["ltiPostMessageStorageJs"];
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

const LtiRegistrationForm = ({
  action,
  children,
}: PropsWithChildren<{
  action: string;
}>): HonoElement => {
  return (
    <form method="post" action={action} class="lti-registration__form">
      {children}
    </form>
  );
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
            <th>Sourced ID</th>
            <th>Roles</th>
            <th>Badge</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {view.members.length === 0 ? (
            <tr>
              <td colspan={canIssue ? 7 : 6} class="lti-launch__bulk-empty">
                No learner members returned by LMS roster for this launch.
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
                <td>{member.sourcedId ?? "Not provided"}</td>
                <td>{member.roleSummary.length === 0 ? "Not provided" : member.roleSummary}</td>
                <td>{badgeIssuanceStatus(member)}</td>
                <td>{member.status ?? "Not provided"}</td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );

  return (
    <LtiLaunchCard stack={true}>
      <h2 class="lti-launch__bulk-title">Issue badges from Sakai roster</h2>
      <p class="lti-launch__hint">
        Select learner members from the Sakai roster and issue the placed badge.
      </p>
      <p class={`lti-launch__bulk-status lti-launch__bulk-status--${view.status}`}>
        {view.message}
      </p>
      <dl class="lti-launch__bulk-meta">
        <DetailRows
          rows={[
            {
              label: "Badge template",
              value: view.badgeTemplateId ?? "Not provided in placement URL",
            },
            {
              label: "Course context",
              value: view.courseContextTitle ?? "Not provided",
            },
            {
              label: "Course context ID",
              value: view.courseContextId ?? "Not provided",
            },
            {
              label: "Roster endpoint",
              value: view.contextMembershipsUrl ?? "Not provided",
            },
            {
              label: "Learner members",
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
                {String(missingEmailCount)} learner member{missingEmailCount === 1 ? "" : "s"}{" "}
                cannot be selected because Sakai did not provide an email address.
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
}): AppPage => {
  return ltiPage({
    title: "LTI Launch Complete | CredTrail",
    body: (
      <section class="lti-launch">
        <header class="lti-launch__hero">
          <h1>LTI 1.3 launch complete</h1>
          <p>
            Launch accepted for <strong>{ltiRoleLabel(input.roleKind)}</strong>.
          </p>
        </header>
        <LtiLaunchCard>
          <dl class="lti-launch__details">
            <DetailRows
              rows={[
                { label: "Issuer", value: input.issuer },
                { label: "Deployment ID", value: input.deploymentId },
                { label: "Tenant", value: input.tenantId },
                { label: "User ID", value: input.userId },
                { label: "Membership role", value: input.membershipRole },
                { label: "Learner profile", value: input.learnerProfileId },
                { label: "LTI subject", value: input.subjectId },
                { label: "Message type", value: input.messageType },
                { label: "Target link URI", value: input.targetLinkUri },
              ]}
            />
          </dl>
        </LtiLaunchCard>
        <LtiLaunchCard stack={true}>
          <p class="lti-launch__hint">
            LTI identity is linked and this browser is now signed into CredTrail.
          </p>
          <p class="lti-launch__link-row">
            <a href={input.dashboardPath} target="_blank" rel="noopener noreferrer">
              Open learner dashboard
            </a>
          </p>
        </LtiLaunchCard>
        <BulkIssuanceSection view={input.bulkIssuanceView} />
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
          <p>Processed selected Sakai roster members for the placed badge.</p>
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
}): AppPage => {
  return ltiPage({
    title: "LTI Issuer Registrations | CredTrail",
    body: (
      <section class="lti-registration">
        <h1 class="lti-registration__title">Manual LTI issuer registration configuration</h1>
        <p class="lti-registration__lede">
          Configure issuer mappings used by LTI 1.3 OIDC login and launch. Stored registrations
          override env-based defaults.
        </p>
        {input.submissionError === undefined ? null : (
          <p class="lti-registration__error">{input.submissionError}</p>
        )}
        <LtiRegistrationForm action="/admin/lti/issuer-registrations">
          <input type="hidden" name="token" value={input.token} />
          <label class="lti-registration__field">
            <span>Issuer URL</span>
            <input name="issuer" type="url" required value={input.formState?.issuer ?? ""} />
          </label>
          <label class="lti-registration__field">
            <span>Tenant ID</span>
            <input name="tenantId" type="text" required value={input.formState?.tenantId ?? ""} />
          </label>
          <label class="lti-registration__field">
            <span>Client ID</span>
            <input name="clientId" type="text" required value={input.formState?.clientId ?? ""} />
          </label>
          <label class="lti-registration__field">
            <span>Authorization endpoint</span>
            <input
              name="authorizationEndpoint"
              type="url"
              required
              value={input.formState?.authorizationEndpoint ?? ""}
            />
          </label>
          <label class="lti-registration__field">
            <span>Platform JWKS endpoint</span>
            <input
              name="platformJwksEndpoint"
              type="url"
              value={input.formState?.platformJwksEndpoint ?? ""}
            />
          </label>
          <label class="lti-registration__field">
            <span>Token endpoint</span>
            <input name="tokenEndpoint" type="url" value={input.formState?.tokenEndpoint ?? ""} />
          </label>
          <div class="lti-registration__actions">
            <LtiSubmitButton>Save registration</LtiSubmitButton>
          </div>
        </LtiRegistrationForm>
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
              {input.registrations.length === 0 ? (
                <tr>
                  <td colspan={7} class="lti-registration__empty">
                    No LTI issuer registrations configured.
                  </td>
                </tr>
              ) : (
                input.registrations.map((registration) => (
                  <tr key={`${registration.issuer}:${registration.clientId}`}>
                    <td class="lti-registration__wrap-anywhere">{registration.issuer}</td>
                    <td>{registration.tenantId}</td>
                    <td class="lti-registration__wrap-anywhere">{registration.clientId}</td>
                    <td class="lti-registration__wrap-anywhere">
                      {registration.authorizationEndpoint}
                    </td>
                    <td class="lti-registration__wrap-anywhere">
                      {registration.platformJwksEndpoint ?? "Not configured"}
                    </td>
                    <td class="lti-registration__wrap-anywhere">
                      {registration.tokenEndpoint ?? "Not configured"}
                    </td>
                    <td>
                      <form method="post" action="/admin/lti/issuer-registrations/delete">
                        <input type="hidden" name="token" value={input.token} />
                        <input type="hidden" name="issuer" value={registration.issuer} />
                        <LtiSubmitButton>Delete</LtiSubmitButton>
                      </form>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    ),
  });
};
