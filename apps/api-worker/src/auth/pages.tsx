import { appPage, type AppPage } from "../ui/render-page";
import type { PropsWithChildren } from "hono/jsx";
import type { HtmlEscapedString } from "hono/utils/html";
import { CtButton, CtButtonLink } from "../ui/actions";
import type { AccessibleTenantContextView } from "./tenant-context-selection";

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;

interface EnterpriseProviderView {
  id: string;
  label: string;
  protocol: "oidc";
  isDefault: boolean;
  startPath: string;
}

interface HostedSocialProviderView {
  id: "google";
  label: string;
  startPath: string;
}

const authPage = (input: {
  title: string;
  body: HonoElement;
  includeLoginScript?: boolean;
  head?: HonoElement | undefined;
}): AppPage => {
  return appPage({
    title: input.title,
    body: input.body,
    assets: input.includeLoginScript === true ? ["authLoginCss", "authLoginJs"] : ["authLoginCss"],
    ...(input.head === undefined ? {} : { head: input.head }),
    variant: "open",
  });
};

const LoginSubmitButton = ({ children }: PropsWithChildren): HonoElement => {
  return (
    <CtButton type="submit" className="ct-login__submit" variant="primary" size="lg">
      {children}
    </CtButton>
  );
};

const LoginActionLink = ({
  href,
  className,
  children,
}: PropsWithChildren<{
  href: string;
  className?: string | undefined;
}>): HonoElement => {
  return (
    <CtButtonLink
      className={className ?? "ct-login__submit"}
      href={href}
      variant="primary"
      size="lg"
    >
      {children}
    </CtButtonLink>
  );
};

const GoogleGMark = (): HonoElement => {
  return (
    <svg class="ct-login__google-mark" aria-hidden="true" focusable="false" viewBox="0 0 18 18">
      <path
        fill="#4285F4"
        d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92c1.7-1.57 2.68-3.88 2.68-6.62Z"
      />
      <path
        fill="#34A853"
        d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.35 0-4.34-1.58-5.05-3.72H.94v2.33A9 9 0 0 0 9 18Z"
      />
      <path
        fill="#FBBC05"
        d="M3.95 10.7A5.4 5.4 0 0 1 3.67 9c0-.59.1-1.16.28-1.7V4.97H.94A9 9 0 0 0 0 9c0 1.45.34 2.82.94 4.03l3.01-2.33Z"
      />
      <path
        fill="#EA4335"
        d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58C13.46.9 11.43 0 9 0A9 9 0 0 0 .94 4.97L3.95 7.3C4.66 5.16 6.65 3.58 9 3.58Z"
      />
    </svg>
  );
};

const adminTenantLabelFromNextPath = (tenantId: string, nextPath: string): string => {
  const adminPathMatch = /^\/tenants\/([^/]+)\/admin(?:$|[/?#])/.exec(nextPath);

  if (adminPathMatch?.[1] === undefined) {
    return tenantId.trim();
  }

  try {
    return decodeURIComponent(adminPathMatch[1]);
  } catch {
    return adminPathMatch[1];
  }
};

const effectiveTenantIdFromInput = (tenantId: string, adminTenantLabel: string): string => {
  return tenantId.trim().length === 0 && adminTenantLabel.trim().length > 0
    ? adminTenantLabel.trim()
    : tenantId.trim();
};

const tenantShowcaseHref = (tenantId: string): string => {
  return tenantId.length === 0 ? "/" : `/showcase/${encodeURIComponent(tenantId)}`;
};

const tenantShowcaseLabel = (tenantId: string): string => {
  return tenantId.length === 0 ? "Back to home" : `View ${tenantId} badge showcase`;
};

const localLoginPath = (input: { tenantId: string; nextPath: string }): string => {
  const params = new URLSearchParams({
    tenantId: input.tenantId,
    next: input.nextPath,
  });

  return `/login?${params.toString()}`;
};

const LoginReasonNotice = (input: {
  reason?: string | undefined;
  hasExplicitNotice: boolean;
}): HonoElement | null => {
  if (input.reason === "sso_failed") {
    return (
      <p class="ct-login__context">
        Institution sign-in did not complete. Try again or contact your CredTrail administrator.
      </p>
    );
  }

  if (input.reason === "google_failed") {
    return (
      <p class="ct-login__context">
        Google sign-in did not complete. Try again or use an email sign-in link.
      </p>
    );
  }

  if (input.reason === "google_unavailable") {
    return (
      <p class="ct-login__context">
        Google sign-in is not configured for this CredTrail environment.
      </p>
    );
  }

  if (input.reason === "sso_required") {
    return <p class="ct-login__context">Institution sign-in is required for this tenant.</p>;
  }

  if (input.reason === "sso_unavailable" && !input.hasExplicitNotice) {
    return (
      <p class="ct-login__context">
        Hosted institution sign-in is not available for this tenant right now. Contact your
        CredTrail administrator.
      </p>
    );
  }

  return null;
};

const EnterpriseSignIn = (input: {
  providers: readonly EnterpriseProviderView[];
}): HonoElement | null => {
  if (input.providers.length === 0) {
    return null;
  }

  return (
    <section class="ct-stack" aria-labelledby="enterprise-sso-title">
      <h2 id="enterprise-sso-title" class="ct-login__form-title">
        Institution sign-in
      </h2>
      <p class="ct-login__form-text">
        Continue through your institution identity provider. Your administrator manages this hosted
        enterprise connection.
      </p>
      <div id="enterprise-sso-options" class="ct-stack">
        {input.providers.map((provider) => {
          return (
            <LoginActionLink href={provider.startPath}>
              Continue with {provider.label}
            </LoginActionLink>
          );
        })}
      </div>
    </section>
  );
};

const HostedSocialSignIn = (input: {
  providers: readonly HostedSocialProviderView[];
}): HonoElement | null => {
  if (input.providers.length === 0) {
    return null;
  }

  return (
    <section class="ct-stack" aria-labelledby="hosted-social-sign-in-title">
      <h2 id="hosted-social-sign-in-title" class="ct-login__form-title">
        Faster sign-in
      </h2>
      <div class="ct-stack">
        {input.providers.map((provider) => {
          return (
            <LoginActionLink
              href={provider.startPath}
              className="ct-login__submit ct-login__submit--google"
            >
              <GoogleGMark />
              <span>Continue with {provider.label}</span>
            </LoginActionLink>
          );
        })}
      </div>
    </section>
  );
};

const MagicLinkTurnstile = (input: { siteKey?: string | undefined }): HonoElement | null => {
  const siteKey = input.siteKey?.trim();

  if (siteKey === undefined || siteKey.length === 0) {
    return null;
  }

  return <div id="magic-link-turnstile" class="cf-turnstile" data-sitekey={siteKey} hidden></div>;
};

const AccessContextNotice = (input: {
  reason?: string | undefined;
  adminTenantLabel: string;
  nextPath: string;
}): HonoElement | null => {
  const adminPathMatch = /^\/tenants\/([^/]+)\/admin(?:$|[/?#])/.exec(input.nextPath);

  if (adminPathMatch === null) {
    return null;
  }

  return (
    <p class="ct-login__context">
      {input.reason === "auth_required" ? "Sign in required." : "Continue sign-in."} You are opening{" "}
      <strong>{input.adminTenantLabel}</strong> institution admin. Use an email that already has
      access.
    </p>
  );
};

const MagicLinkEmailSignIn = (input: {
  adminTenantLabel: string;
  effectiveTenantId: string;
  nextPath: string;
  reason?: string | undefined;
  turnstileSiteKey?: string | undefined;
}): HonoElement => {
  return (
    <section class="ct-stack" aria-labelledby="magic-link-login-title">
      <h2 id="magic-link-login-title" class="ct-login__form-title">
        Email sign-in
      </h2>
      <AccessContextNotice
        adminTenantLabel={input.adminTenantLabel}
        nextPath={input.nextPath}
        reason={input.reason}
      />
      <form id="magic-link-login-form" class="ct-login__form ct-stack">
        <input
          id="magic-link-login-tenant"
          name="tenantId"
          type="hidden"
          value={input.effectiveTenantId}
        />
        <label class="ct-login__field ct-stack">
          <span>Institution email</span>
          <input name="email" type="email" required placeholder="name@institution.edu" />
        </label>
        <div id="magic-link-tenant-selection" class="ct-login__tenant-selection ct-stack" hidden>
          <p class="ct-login__tenant-selection-title">Choose your institution</p>
          <div id="magic-link-tenant-options" class="ct-login__tenant-options"></div>
        </div>
        <input name="next" type="hidden" value={input.nextPath} />
        <MagicLinkTurnstile siteKey={input.turnstileSiteKey} />
        <LoginSubmitButton>Continue</LoginSubmitButton>
      </form>
      <p class="ct-login__help">Sign-in links expire in 10 minutes.</p>
      <p id="magic-link-login-status" class="ct-login__status" hidden></p>
      <p id="magic-link-dev-link" class="ct-login__dev"></p>
    </section>
  );
};

const ExplicitLocalFallback = (input: {
  explicitLocalLoginPath: string | null;
}): HonoElement | null => {
  if (input.explicitLocalLoginPath === null) {
    return null;
  }

  return (
    <p class="ct-login__help">
      Institution SSO is required for normal access. If your institution administrator designated
      your account for emergency fallback access, use{" "}
      <a href={input.explicitLocalLoginPath}>break-glass local sign-in</a>.
    </p>
  );
};

const loginIntroText = (input: {
  hasEnterpriseProviders: boolean;
  localLoginAllowed: boolean;
}): string => {
  if (!input.hasEnterpriseProviders) {
    return "Enter your email to receive a secure sign-in link.";
  }

  return input.localLoginAllowed
    ? "Choose your institution sign-in or request a hosted CredTrail sign-in link."
    : "Continue with your institution sign-in to open CredTrail.";
};

export const magicLinkLoginPage = (input: {
  tenantId: string;
  nextPath: string;
  reason?: string;
  localLoginAllowed?: boolean;
  explicitLocalLoginPath?: string | null;
  enterpriseProviders?: readonly EnterpriseProviderView[];
  hostedSocialProviders?: readonly HostedSocialProviderView[];
  notice?: string;
  turnstileSiteKey?: string | undefined;
}): AppPage => {
  const adminTenantLabel = adminTenantLabelFromNextPath(input.tenantId, input.nextPath);
  const effectiveTenantId = effectiveTenantIdFromInput(input.tenantId, adminTenantLabel);
  const enterpriseProviders = input.enterpriseProviders ?? [];
  const hostedSocialProviders = input.hostedSocialProviders ?? [];
  const localLoginAllowed = input.localLoginAllowed ?? true;
  const explicitLocalLoginPath = input.explicitLocalLoginPath ?? null;
  const notice = input.notice?.trim() ?? "";
  const hasExplicitNotice = notice.length > 0;
  const turnstileSiteKey = input.turnstileSiteKey?.trim();
  const hasTurnstile = turnstileSiteKey !== undefined && turnstileSiteKey.length > 0;

  return authPage({
    title: "Sign In · CredTrail",
    includeLoginScript: true,
    head: hasTurnstile ? (
      <script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
        async
        defer
      ></script>
    ) : undefined,
    body: (
      <section class="ct-login ct-stack">
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
            <p class="ct-login__lede">
              {loginIntroText({
                hasEnterpriseProviders: enterpriseProviders.length > 0,
                localLoginAllowed,
              })}
            </p>
          </div>
          <div class="ct-login__form-wrap ct-stack">
            <LoginReasonNotice reason={input.reason} hasExplicitNotice={hasExplicitNotice} />
            {!hasExplicitNotice ? null : <p class="ct-login__context">{notice}</p>}
            <HostedSocialSignIn providers={hostedSocialProviders} />
            <EnterpriseSignIn providers={enterpriseProviders} />
            {!localLoginAllowed ? null : (
              <MagicLinkEmailSignIn
                adminTenantLabel={adminTenantLabel}
                effectiveTenantId={effectiveTenantId}
                nextPath={input.nextPath}
                reason={input.reason}
                turnstileSiteKey={turnstileSiteKey}
              />
            )}
            <ExplicitLocalFallback explicitLocalLoginPath={explicitLocalLoginPath} />
            <p class="ct-login__back">
              <a href={tenantShowcaseHref(effectiveTenantId)}>
                {tenantShowcaseLabel(effectiveTenantId)}
              </a>
            </p>
          </div>
        </div>
      </section>
    ),
  });
};

export const organizationChooserPage = (input: {
  organizations: readonly AccessibleTenantContextView[];
  nextPath: string;
  currentTenantId?: string | null;
}): AppPage => {
  return authPage({
    title: "Choose Organization · CredTrail",
    body: (
      <section class="ct-login ct-stack">
        <div class="ct-login__card">
          <div class="ct-login__header">
            <p class="ct-login__brand">CredTrail</p>
            <h1 class="ct-login__title">Choose your institution</h1>
            <p class="ct-login__lede">
              Your account has access to more than one organization. Select where to continue.
            </p>
          </div>
          <div class="ct-login__form-wrap ct-stack">
            <section class="ct-stack" aria-labelledby="organization-chooser-title">
              <h2 id="organization-chooser-title" class="ct-login__form-title">
                Available organizations
              </h2>
              <ul class="ct-login__organization-list">
                {input.organizations.map((organization) => {
                  const isCurrent = input.currentTenantId === organization.tenantId;
                  const roleLabel =
                    organization.membershipRole === "owner" ? "Owner" : organization.membershipRole;

                  return (
                    <li key={organization.tenantId} class="ct-login__organization-row">
                      <div class="ct-login__organization-copy">
                        <p class="ct-login__organization-name">
                          {organization.tenantDisplayName}
                          {isCurrent ? (
                            <span class="ct-login__organization-current">Current</span>
                          ) : null}
                        </p>
                        <p class="ct-login__organization-meta">
                          {roleLabel} access · {organization.tenantPlanTier}
                        </p>
                      </div>
                      <form method="post" action="/account/organizations/select">
                        <input type="hidden" name="tenantId" value={organization.tenantId} />
                        <input type="hidden" name="next" value={input.nextPath} />
                        <LoginSubmitButton>{isCurrent ? "Reopen" : "Continue"}</LoginSubmitButton>
                      </form>
                    </li>
                  );
                })}
              </ul>
            </section>
            <p class="ct-login__help">
              Need a different organization? Ask an owner or administrator to grant your account
              access.
            </p>
          </div>
        </div>
      </section>
    ),
  });
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

const LocalNotice = (input: { notice: string }): HonoElement | null => {
  return input.notice.length === 0 ? null : <p class="ct-login__context">{input.notice}</p>;
};

export const localBreakGlassLoginPage = (input: {
  tenantId: string;
  nextPath: string;
  reason?: string;
}): AppPage => {
  const notice = localReasonNotice(input.reason);

  return authPage({
    title: "Break-Glass Local Access · CredTrail",
    body: (
      <section class="ct-login ct-stack">
        <div class="ct-login__card">
          <div class="ct-login__header">
            <p class="ct-login__brand">CredTrail</p>
            <h1 class="ct-login__title">Break-glass local sign-in</h1>
            <p class="ct-login__lede">
              Reserved for designated fallback accounts when institution SSO is unavailable.
            </p>
          </div>
          <div class="ct-login__form-wrap ct-stack">
            <LocalNotice notice={notice} />
            <section class="ct-stack" aria-labelledby="break-glass-local-title">
              <h2 id="break-glass-local-title" class="ct-login__form-title">
                Sign in with local credentials
              </h2>
              <form class="ct-login__form ct-stack" method="post" action="/auth/local/sign-in">
                <input type="hidden" name="tenantId" value={input.tenantId} />
                <input type="hidden" name="next" value={input.nextPath} />
                <label class="ct-login__field ct-stack">
                  <span>Institution email</span>
                  <input name="email" type="email" required placeholder="name@institution.edu" />
                </label>
                <label class="ct-login__field ct-stack">
                  <span>Password</span>
                  <input
                    name="password"
                    type="password"
                    required
                    placeholder="Your local break-glass password"
                  />
                </label>
                <LoginSubmitButton>Continue with local access</LoginSubmitButton>
              </form>
            </section>
            <section class="ct-stack" aria-labelledby="break-glass-reset-title">
              <h2 id="break-glass-reset-title" class="ct-login__form-title">
                Set up or reset local access
              </h2>
              <p class="ct-login__form-text">
                If your account is already allowlisted, CredTrail can email you a password-setup
                link.
              </p>
              <form
                class="ct-login__form ct-stack"
                method="post"
                action="/auth/local/reset-password/request"
              >
                <input type="hidden" name="tenantId" value={input.tenantId} />
                <input type="hidden" name="next" value={input.nextPath} />
                <label class="ct-login__field ct-stack">
                  <span>Institution email</span>
                  <input name="email" type="email" required placeholder="name@institution.edu" />
                </label>
                <LoginSubmitButton>Email setup link</LoginSubmitButton>
              </form>
            </section>
            <p class="ct-login__back">
              <a href={localLoginPath({ tenantId: input.tenantId, nextPath: input.nextPath })}>
                Back to tenant sign-in
              </a>
            </p>
          </div>
        </div>
      </section>
    ),
  });
};

export const localResetPasswordPage = (input: {
  tenantId: string;
  nextPath: string;
  token: string;
  reason?: string;
}): AppPage => {
  const notice = localReasonNotice(input.reason);

  return authPage({
    title: "Reset Local Password · CredTrail",
    body: (
      <section class="ct-login ct-stack">
        <div class="ct-login__card">
          <div class="ct-login__header">
            <p class="ct-login__brand">CredTrail</p>
            <h1 class="ct-login__title">Set your local password</h1>
            <p class="ct-login__lede">
              Finish local break-glass setup, then return to sign in and complete MFA enrollment.
            </p>
          </div>
          <div class="ct-login__form-wrap ct-stack">
            <LocalNotice notice={notice} />
            <form class="ct-login__form ct-stack" method="post" action="/auth/local/reset-password">
              <input type="hidden" name="tenantId" value={input.tenantId} />
              <input type="hidden" name="next" value={input.nextPath} />
              <input type="hidden" name="token" value={input.token} />
              <label class="ct-login__field ct-stack">
                <span>New password</span>
                <input name="newPassword" type="password" required minlength={8} />
              </label>
              <LoginSubmitButton>Save password</LoginSubmitButton>
            </form>
          </div>
        </div>
      </section>
    ),
  });
};

const LocalTwoFactorEnrollment = (input: {
  tenantId: string;
  nextPath: string;
  setup?:
    | {
        totpUri: string;
        backupCodes: readonly string[];
      }
    | null
    | undefined;
}): HonoElement => {
  if (input.setup === null || input.setup === undefined) {
    return (
      <form class="ct-login__form ct-stack" method="post" action="/auth/local/two-factor/setup">
        <input type="hidden" name="tenantId" value={input.tenantId} />
        <input type="hidden" name="next" value={input.nextPath} />
        <label class="ct-login__field ct-stack">
          <span>Current password</span>
          <input name="password" type="password" required />
        </label>
        <LoginSubmitButton>Generate authenticator setup</LoginSubmitButton>
      </form>
    );
  }

  return (
    <div class="ct-stack">
      <p class="ct-login__form-text">
        Add this TOTP URI to your authenticator app, then verify one current code below.
      </p>
      <pre class="ct-login__dev">{input.setup.totpUri}</pre>
      {input.setup.backupCodes.length === 0 ? null : (
        <pre class="ct-login__dev">{input.setup.backupCodes.join("\n")}</pre>
      )}
    </div>
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
}): AppPage => {
  const notice = localReasonNotice(input.reason);

  return authPage({
    title: "Local MFA · CredTrail",
    body: (
      <section class="ct-login ct-stack">
        <div class="ct-login__card">
          <div class="ct-login__header">
            <p class="ct-login__brand">CredTrail</p>
            <h1 class="ct-login__title">
              {input.setup === null || input.setup === undefined
                ? "Complete MFA enrollment"
                : "Verify your authenticator code"}
            </h1>
            <p class="ct-login__lede">
              Break-glass local access requires a valid TOTP code before tenant access is granted.
            </p>
          </div>
          <div class="ct-login__form-wrap ct-stack">
            <LocalNotice notice={notice} />
            <LocalTwoFactorEnrollment
              tenantId={input.tenantId}
              nextPath={input.nextPath}
              setup={input.setup}
            />
            <form
              class="ct-login__form ct-stack"
              method="post"
              action="/auth/local/two-factor/verify"
            >
              <input type="hidden" name="tenantId" value={input.tenantId} />
              <input type="hidden" name="next" value={input.nextPath} />
              <label class="ct-login__field ct-stack">
                <span>Authenticator code</span>
                <input
                  name="code"
                  type="text"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  required
                />
              </label>
              <LoginSubmitButton>Verify and continue</LoginSubmitButton>
            </form>
          </div>
        </div>
      </section>
    ),
  });
};
