(() => {
const form = document.getElementById("magic-link-login-form");
const statusEl = document.getElementById("magic-link-login-status");
const devLinkEl = document.getElementById("magic-link-dev-link");
const turnstileEl = document.getElementById("magic-link-turnstile");
const tenantInput = document.getElementById("magic-link-login-tenant");
const tenantSelectionEl = document.getElementById("magic-link-tenant-selection");
const tenantOptionsEl = document.getElementById("magic-link-tenant-options");
const submitButton =
  form instanceof HTMLFormElement ? form.querySelector('button[type="submit"]') : null;
let turnstileWidgetId = null;

if (
  !(form instanceof HTMLFormElement) ||
  !(statusEl instanceof HTMLElement) ||
  !(devLinkEl instanceof HTMLElement) ||
  !(tenantInput instanceof HTMLInputElement)
) {
  return;
}

const setStatus = (text, tone) => {
  statusEl.hidden = false;
  statusEl.textContent = text;
  statusEl.dataset.tone = tone;
};

const isSafeRedirectPath = (path) => {
  return typeof path === "string" && path.startsWith("/") && !path.startsWith("//");
};

const ensureTurnstile = () => {
  if (!(turnstileEl instanceof HTMLElement)) {
    return;
  }

  turnstileEl.hidden = false;

  if (
    turnstileWidgetId !== null ||
    !window.turnstile ||
    typeof window.turnstile.render !== "function"
  ) {
    return;
  }

  turnstileWidgetId = window.turnstile.render(turnstileEl, {
    sitekey: turnstileEl.dataset.sitekey,
  });
};

const setSubmitDisabled = (disabled) => {
  if (submitButton instanceof HTMLButtonElement) {
    submitButton.disabled = disabled;
  }
};

const browserDateTimePreference = () => {
  let preferredLocale = "";
  let preferredTimeZone = "";

  if (Array.isArray(navigator.languages) && typeof navigator.languages[0] === "string") {
    preferredLocale = navigator.languages[0];
  } else if (typeof navigator.language === "string") {
    preferredLocale = navigator.language;
  }

  try {
    if (typeof Intl === "object" && typeof Intl.DateTimeFormat === "function") {
      const resolved = Intl.DateTimeFormat().resolvedOptions();

      if (typeof resolved.timeZone === "string") {
        preferredTimeZone = resolved.timeZone;
      }
    }
  } catch {
    preferredTimeZone = "";
  }

  return {
    preferredLocale,
    preferredTimeZone,
  };
};

const clearTenantSelection = () => {
  if (tenantOptionsEl instanceof HTMLElement) {
    tenantOptionsEl.replaceChildren();
  }

  if (tenantSelectionEl instanceof HTMLElement) {
    tenantSelectionEl.hidden = true;
  }

  setSubmitDisabled(false);
};

const renderTenantSelection = (organizations) => {
  if (!(tenantOptionsEl instanceof HTMLElement) || !(tenantSelectionEl instanceof HTMLElement)) {
    return;
  }

  tenantOptionsEl.replaceChildren();

  for (const organization of organizations) {
    if (
      !organization ||
      typeof organization.tenantId !== "string" ||
      typeof organization.label !== "string"
    ) {
      continue;
    }

    const button = document.createElement("button");
    button.type = "button";
    button.className = "ct-login__tenant-choice";
    button.dataset.tenantId = organization.tenantId;

    const copy = document.createElement("span");
    const name = document.createElement("span");
    name.className = "ct-login__tenant-choice-name";
    name.textContent = organization.label;

    const meta = document.createElement("span");
    meta.className = "ct-login__tenant-choice-meta";
    meta.textContent =
      typeof organization.roleLabel === "string" && organization.roleLabel.length > 0
        ? organization.roleLabel + " access"
        : "Available access";

    const action = document.createElement("span");
    action.className = "ct-login__tenant-choice-action";
    action.textContent = "Choose";

    copy.append(name, meta);
    button.append(copy, action);
    button.addEventListener("click", () => {
      tenantInput.value = organization.tenantId;
      clearTenantSelection();
      form.requestSubmit();
    });
    tenantOptionsEl.append(button);
  }

  const hasTenantOptions = tenantOptionsEl.children.length > 0;
  tenantSelectionEl.hidden = !hasTenantOptions;
  setSubmitDisabled(hasTenantOptions);
};

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setStatus("Checking access...", "info");
  devLinkEl.textContent = "";
  setSubmitDisabled(true);
  const data = new FormData(form);
  const tenantIdRaw = data.get("tenantId");
  const emailRaw = data.get("email");
  const nextRaw = data.get("next");
  const turnstileRaw = data.get("cf-turnstile-response");
  const tenantId = typeof tenantIdRaw === "string" ? tenantIdRaw.trim() : "";
  const email = typeof emailRaw === "string" ? emailRaw.trim().toLowerCase() : "";
  const next = typeof nextRaw === "string" ? nextRaw.trim() : "";
  const turnstileToken = typeof turnstileRaw === "string" ? turnstileRaw.trim() : "";
  const { preferredLocale, preferredTimeZone } = browserDateTimePreference();

  if (email.length === 0) {
    setStatus("Enter your institution email.", "error");
    setSubmitDisabled(false);
    return;
  }

  try {
    const response = await fetch("/v1/auth/magic-link/request", {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        email,
        ...(tenantId.length === 0 ? {} : { tenantId }),
        ...(isSafeRedirectPath(next) ? { nextPath: next } : {}),
        ...(turnstileToken.length === 0 ? {} : { turnstileToken }),
        ...(preferredLocale.length === 0 ? {} : { preferredLocale }),
        ...(preferredTimeZone.length === 0 ? {} : { preferredTimeZone }),
      }),
    });
    const payload = await response.json().catch(() => null);

    if (
      response.ok &&
      payload &&
      payload.status === "tenant_selection_required" &&
      Array.isArray(payload.organizations)
    ) {
      setStatus("Choose your institution to continue.", "info");
      renderTenantSelection(payload.organizations);
      return;
    }

    if (!response.ok) {
      if (payload && payload.turnstileRequired === true) {
        ensureTurnstile();
      }
      if (payload && isSafeRedirectPath(payload.loginPath)) {
        window.location.assign(payload.loginPath);
        return;
      }
      const detail =
        payload && typeof payload.error === "string" ? payload.error : "Request failed";
      setStatus(detail, "error");
      setSubmitDisabled(false);
      return;
    }

    clearTenantSelection();
    const deliveryStatus =
      payload && typeof payload.deliveryStatus === "string" ? payload.deliveryStatus : "sent";
    setStatus(
      deliveryStatus === "sent"
        ? "Check your inbox for a sign-in link from CredTrail. It expires in 10 minutes."
        : deliveryStatus === "failed"
          ? "Your sign-in link was created, but the email could not be delivered. Contact support."
          : "Your sign-in link is ready.",
      deliveryStatus === "failed" ? "error" : "success",
    );

    if (payload && typeof payload.magicLinkUrl === "string" && payload.magicLinkUrl.length > 0) {
      const url = new URL(payload.magicLinkUrl);
      if (isSafeRedirectPath(next)) {
        url.searchParams.set("next", next);
      }
      devLinkEl.innerHTML =
        '<a href="' + url.toString() + '">Open sign-in link (development helper)</a>';
    }
  } catch {
    setStatus("We could not send the sign-in link right now. Please try again.", "error");
    setSubmitDisabled(false);
  }
});

})();