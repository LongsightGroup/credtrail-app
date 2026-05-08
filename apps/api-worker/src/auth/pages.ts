import { renderPageShell } from "@credtrail/ui-components";
import type { AccessibleTenantContextView } from "./tenant-context-selection";
import { renderPageAssetTags } from "../ui/page-assets";
import { escapeHtml } from "../utils/display-format";

export const magicLinkLoginPage = (input: {
  tenantId: string;
  nextPath: string;
  reason?: string;
  localLoginAllowed?: boolean;
  explicitLocalLoginPath?: string | null;
  enterpriseProviders?: readonly {
    id: string;
    label: string;
    protocol: "oidc" | "saml";
    isDefault: boolean;
    startPath: string;
  }[];
  notice?: string;
  turnstileSiteKey?: string | undefined;
}): string => {
  const adminPathMatch = /^\/tenants\/([^/]+)\/admin(?:$|[/?#])/.exec(input.nextPath);
  let adminTenantLabel = input.tenantId.trim();

  if (adminPathMatch?.[1] !== undefined) {
    try {
      adminTenantLabel = decodeURIComponent(adminPathMatch[1]);
    } catch {
      adminTenantLabel = adminPathMatch[1];
    }
  }

  const effectiveTenantId =
    input.tenantId.trim().length === 0 && adminTenantLabel.trim().length > 0
      ? adminTenantLabel.trim()
      : input.tenantId.trim();

  const accessContextNotice =
    adminPathMatch === null
      ? ""
      : `<p class="ct-login__context">
          ${input.reason === "auth_required" ? "Sign in required." : "Continue sign-in."}
          You are opening <strong>${escapeHtml(adminTenantLabel)}</strong> institution admin. Use an email that already has access.
        </p>`;
  const tenantLinkHref =
    effectiveTenantId.length === 0 ? "/" : `/showcase/${encodeURIComponent(effectiveTenantId)}`;
  const tenantLinkLabel =
    effectiveTenantId.length === 0
      ? "Back to home"
      : `View ${escapeHtml(effectiveTenantId)} badge showcase`;
  const enterpriseProviders = input.enterpriseProviders ?? [];
  const localLoginAllowed = input.localLoginAllowed ?? true;
  const explicitLocalLoginPath = input.explicitLocalLoginPath ?? null;
  const hasExplicitNotice = (input.notice ?? "").trim().length > 0;
  const turnstileSiteKey = input.turnstileSiteKey?.trim();
  const turnstileMarkup =
    turnstileSiteKey === undefined || turnstileSiteKey.length === 0
      ? ""
      : `<div
              id="magic-link-turnstile"
              class="cf-turnstile"
              data-sitekey="${escapeHtml(turnstileSiteKey)}"
              hidden
            ></div>`;
  const turnstileScript =
    turnstileSiteKey === undefined || turnstileSiteKey.length === 0
      ? ""
      : '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit" async defer></script>';
  const loginReasonNotice =
    input.reason === "sso_failed"
      ? '<p class="ct-login__context">Institution sign-in did not complete. Try again or contact your CredTrail administrator.</p>'
      : input.reason === "sso_required"
        ? '<p class="ct-login__context">Institution sign-in is required for this tenant.</p>'
        : input.reason === "sso_unavailable" && !hasExplicitNotice
          ? '<p class="ct-login__context">Hosted institution sign-in is not available for this tenant right now. Contact your CredTrail administrator.</p>'
          : "";
  const enterpriseSignInMarkup =
    enterpriseProviders.length === 0
      ? ""
      : `<section class="ct-stack" aria-labelledby="enterprise-sso-title">
          <h2 id="enterprise-sso-title" class="ct-login__form-title">Institution sign-in</h2>
          <p class="ct-login__form-text">
            Continue through your institution identity provider. Your administrator manages this hosted enterprise connection.
          </p>
          <div id="enterprise-sso-options" class="ct-stack">
            ${enterpriseProviders
              .map((provider) => {
                return `<a class="ct-login__submit" href="${escapeHtml(provider.startPath)}">
                  Continue with ${escapeHtml(provider.label)}
                </a>`;
              })
              .join("")}
          </div>
        </section>`;
  const localLoginMarkup = !localLoginAllowed
    ? ""
    : `<section class="ct-stack" aria-labelledby="magic-link-login-title">
          <h2 id="magic-link-login-title" class="ct-login__form-title">Email sign-in</h2>
          ${accessContextNotice}
          <form id="magic-link-login-form" class="ct-login__form ct-stack">
            <input id="magic-link-login-tenant" name="tenantId" type="hidden" value="${escapeHtml(effectiveTenantId)}" />
            <label class="ct-login__field ct-stack">
              <span>Institution email</span>
              <input name="email" type="email" required placeholder="name@institution.edu" />
            </label>
            <div id="magic-link-tenant-selection" class="ct-login__tenant-selection ct-stack" hidden>
              <p class="ct-login__tenant-selection-title">Choose your institution</p>
              <div id="magic-link-tenant-options" class="ct-login__tenant-options"></div>
            </div>
            <input name="next" type="hidden" value="${escapeHtml(input.nextPath)}" />
            ${turnstileMarkup}
            <button type="submit" class="ct-login__submit">Continue</button>
          </form>
          <p class="ct-login__help">
            Sign-in links expire in 10 minutes.
          </p>
          <p id="magic-link-login-status" class="ct-login__status" hidden></p>
          <p id="magic-link-dev-link" class="ct-login__dev"></p>
        </section>`;
  const explicitLocalFallbackMarkup =
    explicitLocalLoginPath === null
      ? ""
      : `<p class="ct-login__help">
          Institution SSO is required for normal access.
          If your institution administrator designated your account for emergency fallback access, use
          <a href="${escapeHtml(explicitLocalLoginPath)}">break-glass local sign-in</a>.
        </p>`;
  const loginIntroText =
    enterpriseProviders.length > 0
      ? localLoginAllowed
        ? "Choose your institution sign-in or request a hosted CredTrail sign-in link."
        : "Continue with your institution sign-in to open CredTrail."
      : "Enter your email to receive a secure sign-in link.";
  return renderPageShell(
    "Sign In · CredTrail",
    `<section class="ct-login ct-stack">
      <div class="ct-login__card ct-login__card--split">
        <div class="ct-login__record-panel" aria-hidden="true">
          <p class="ct-login__record-kicker">Verified access</p>
          <div class="ct-login__record-seal">
            <span>OB3</span>
            <strong>Verified</strong>
          </div>
          <div class="ct-login__record-summary">
            <span>Institution credential access</span>
            <span>Secure sign-in link</span>
            <span>Open Badges 3.0</span>
          </div>
          <p class="ct-login__record-caption">Open Badges 3.0 credential infrastructure</p>
        </div>
        <div class="ct-login__header">
          <p class="ct-login__brand">CredTrail</p>
          <h1 class="ct-login__title">Sign in with your institution email</h1>
          <p class="ct-login__lede">${loginIntroText}</p>
        </div>
        <div class="ct-login__form-wrap ct-stack">
          ${loginReasonNotice}
          ${!hasExplicitNotice ? "" : `<p class="ct-login__context">${escapeHtml(input.notice ?? "")}</p>`}
          ${enterpriseSignInMarkup}
          ${localLoginMarkup}
          ${explicitLocalFallbackMarkup}
          <p class="ct-login__back">
            <a href="${tenantLinkHref}">${tenantLinkLabel}</a>
          </p>
        </div>
      </div>
    </section>`,
    `${renderPageAssetTags(["foundationCss", "authLoginCss", "authLoginJs"])}
    ${turnstileScript}`,
    "open",
  );
};

export const organizationChooserPage = (input: {
  organizations: readonly AccessibleTenantContextView[];
  nextPath: string;
  currentTenantId?: string | null;
}): string => {
  const organizationRows = input.organizations
    .map((organization) => {
      const isCurrent = input.currentTenantId === organization.tenantId;
      const roleLabel =
        organization.membershipRole === "owner" ? "Owner" : organization.membershipRole;

      return `<li class="ct-login__organization-row">
        <div class="ct-login__organization-copy">
          <p class="ct-login__organization-name">
            ${escapeHtml(organization.tenantDisplayName)}
            ${isCurrent ? '<span class="ct-login__organization-current">Current</span>' : ""}
          </p>
          <p class="ct-login__organization-meta">
            ${escapeHtml(roleLabel)} access · ${escapeHtml(organization.tenantPlanTier)}
          </p>
        </div>
        <form method="post" action="/account/organizations/select">
          <input type="hidden" name="tenantId" value="${escapeHtml(organization.tenantId)}" />
          <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
          <button type="submit" class="ct-login__submit">${isCurrent ? "Reopen" : "Continue"}</button>
        </form>
      </li>`;
    })
    .join("");

  return renderPageShell(
    "Choose Organization · CredTrail",
    `<section class="ct-login ct-stack">
      <div class="ct-login__card">
        <div class="ct-login__header">
          <p class="ct-login__brand">CredTrail</p>
          <h1 class="ct-login__title">Choose your institution</h1>
          <p class="ct-login__lede">Your account has access to more than one organization. Select where to continue.</p>
        </div>
        <div class="ct-login__form-wrap ct-stack">
          <section class="ct-stack" aria-labelledby="organization-chooser-title">
            <h2 id="organization-chooser-title" class="ct-login__form-title">Available organizations</h2>
            <ul class="ct-login__organization-list">
              ${organizationRows}
            </ul>
          </section>
          <p class="ct-login__help">
            Need a different organization? Ask an owner or administrator to grant your account access.
          </p>
        </div>
      </div>
    </section>`,
    renderPageAssetTags(["foundationCss", "authLoginCss"]),
    "open",
  );
};

const localReasonNotice = (reason: string | undefined): string => {
  switch (reason) {
    case "break_glass_invalid_credentials":
      return "Local sign-in did not complete. Check your email, password, and break-glass eligibility.";
    case "break_glass_invalid_code":
      return "The verification code was not accepted. Try again with a fresh code.";
    case "break_glass_invalid_password":
      return "Current password was not accepted for MFA enrollment.";
    case "break_glass_not_authenticated":
      return "Sign in locally before completing MFA enrollment.";
    case "break_glass_not_allowlisted":
      return "This account is not currently approved for break-glass local access.";
    case "break_glass_mfa_setup_pending":
      return "Finish local MFA enrollment before CredTrail grants tenant access.";
    case "break_glass_unavailable":
      return "Break-glass local access is not available for this tenant.";
    case "password_reset_complete":
      return "Password updated. Sign in locally and complete MFA enrollment before using break-glass access.";
    case "reset_sent":
      return "If this email is approved for break-glass access, a setup link has been sent.";
    default:
      return "";
  }
};

export const localBreakGlassLoginPage = (input: {
  tenantId: string;
  nextPath: string;
  reason?: string;
}): string => {
  const notice = localReasonNotice(input.reason);

  return renderPageShell(
    "Break-Glass Local Access · CredTrail",
    `<section class="ct-login ct-stack">
      <div class="ct-login__card">
        <div class="ct-login__header">
          <p class="ct-login__brand">CredTrail</p>
          <h1 class="ct-login__title">Break-glass local sign-in</h1>
          <p class="ct-login__lede">Reserved for designated fallback accounts when institution SSO is unavailable.</p>
        </div>
        <div class="ct-login__form-wrap ct-stack">
          ${notice.length === 0 ? "" : `<p class="ct-login__context">${escapeHtml(notice)}</p>`}
          <section class="ct-stack" aria-labelledby="break-glass-local-title">
            <h2 id="break-glass-local-title" class="ct-login__form-title">Sign in with local credentials</h2>
            <form class="ct-login__form ct-stack" method="post" action="/auth/local/sign-in">
              <input type="hidden" name="tenantId" value="${escapeHtml(input.tenantId)}" />
              <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
              <label class="ct-login__field ct-stack">
                <span>Institution email</span>
                <input name="email" type="email" required placeholder="name@institution.edu" />
              </label>
              <label class="ct-login__field ct-stack">
                <span>Password</span>
                <input name="password" type="password" required placeholder="Your local break-glass password" />
              </label>
              <button type="submit" class="ct-login__submit">Continue with local access</button>
            </form>
          </section>
          <section class="ct-stack" aria-labelledby="break-glass-reset-title">
            <h2 id="break-glass-reset-title" class="ct-login__form-title">Set up or reset local access</h2>
            <p class="ct-login__form-text">
              If your account is already allowlisted, CredTrail can email you a password-setup link.
            </p>
            <form class="ct-login__form ct-stack" method="post" action="/auth/local/reset-password/request">
              <input type="hidden" name="tenantId" value="${escapeHtml(input.tenantId)}" />
              <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
              <label class="ct-login__field ct-stack">
                <span>Institution email</span>
                <input name="email" type="email" required placeholder="name@institution.edu" />
              </label>
              <button type="submit" class="ct-login__submit">Email setup link</button>
            </form>
          </section>
          <p class="ct-login__back">
            <a href="/login?tenantId=${encodeURIComponent(input.tenantId)}&next=${encodeURIComponent(
              input.nextPath,
            )}">Back to tenant sign-in</a>
          </p>
        </div>
      </div>
    </section>`,
    renderPageAssetTags(["foundationCss", "authLoginCss"]),
  );
};

export const localResetPasswordPage = (input: {
  tenantId: string;
  nextPath: string;
  token: string;
  reason?: string;
}): string => {
  const notice = localReasonNotice(input.reason);

  return renderPageShell(
    "Reset Local Password · CredTrail",
    `<section class="ct-login ct-stack">
      <div class="ct-login__card">
        <div class="ct-login__header">
          <p class="ct-login__brand">CredTrail</p>
          <h1 class="ct-login__title">Set your local password</h1>
          <p class="ct-login__lede">Finish local break-glass setup, then return to sign in and complete MFA enrollment.</p>
        </div>
        <div class="ct-login__form-wrap ct-stack">
          ${notice.length === 0 ? "" : `<p class="ct-login__context">${escapeHtml(notice)}</p>`}
          <form class="ct-login__form ct-stack" method="post" action="/auth/local/reset-password">
            <input type="hidden" name="tenantId" value="${escapeHtml(input.tenantId)}" />
            <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
            <input type="hidden" name="token" value="${escapeHtml(input.token)}" />
            <label class="ct-login__field ct-stack">
              <span>New password</span>
              <input name="newPassword" type="password" required minlength="8" />
            </label>
            <button type="submit" class="ct-login__submit">Save password</button>
          </form>
        </div>
      </div>
    </section>`,
    renderPageAssetTags(["foundationCss", "authLoginCss"]),
  );
};

export const localTwoFactorPage = (input: {
  tenantId: string;
  nextPath: string;
  reason?: string;
  setup?: {
    totpUri: string;
    backupCodes: readonly string[];
  } | null;
}): string => {
  const notice = localReasonNotice(input.reason);
  const enrollmentMarkup =
    input.setup === null || input.setup === undefined
      ? `<form class="ct-login__form ct-stack" method="post" action="/auth/local/two-factor/setup">
          <input type="hidden" name="tenantId" value="${escapeHtml(input.tenantId)}" />
          <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
          <label class="ct-login__field ct-stack">
            <span>Current password</span>
            <input name="password" type="password" required />
          </label>
          <button type="submit" class="ct-login__submit">Generate authenticator setup</button>
        </form>`
      : `<div class="ct-stack">
          <p class="ct-login__form-text">
            Add this TOTP URI to your authenticator app, then verify one current code below.
          </p>
          <pre class="ct-login__dev" style="white-space:pre-wrap;">${escapeHtml(
            input.setup.totpUri,
          )}</pre>
          ${
            input.setup.backupCodes.length === 0
              ? ""
              : `<pre class="ct-login__dev" style="white-space:pre-wrap;">${escapeHtml(
                  input.setup.backupCodes.join("\n"),
                )}</pre>`
          }
        </div>`;

  return renderPageShell(
    "Local MFA · CredTrail",
    `<section class="ct-login ct-stack">
      <div class="ct-login__card">
        <div class="ct-login__header">
          <p class="ct-login__brand">CredTrail</p>
          <h1 class="ct-login__title">${
            input.setup === null || input.setup === undefined
              ? "Complete MFA enrollment"
              : "Verify your authenticator code"
          }</h1>
          <p class="ct-login__lede">Break-glass local access requires a valid TOTP code before tenant access is granted.</p>
        </div>
        <div class="ct-login__form-wrap ct-stack">
          ${notice.length === 0 ? "" : `<p class="ct-login__context">${escapeHtml(notice)}</p>`}
          ${enrollmentMarkup}
          <form class="ct-login__form ct-stack" method="post" action="/auth/local/two-factor/verify">
            <input type="hidden" name="tenantId" value="${escapeHtml(input.tenantId)}" />
            <input type="hidden" name="next" value="${escapeHtml(input.nextPath)}" />
            <label class="ct-login__field ct-stack">
              <span>Authenticator code</span>
              <input name="code" type="text" inputmode="numeric" autocomplete="one-time-code" required />
            </label>
            <button type="submit" class="ct-login__submit">Verify and continue</button>
          </form>
        </div>
      </div>
    </section>`,
    renderPageAssetTags(["foundationCss", "authLoginCss"]),
  );
};
