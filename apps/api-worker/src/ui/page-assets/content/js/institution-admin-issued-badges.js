const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const assertionsApiPathPrefix =
  typeof parsedContext.assertionsApiPathPrefix === "string"
    ? parsedContext.assertionsApiPathPrefix
    : "";
const issuedBadgeLifecyclePanel = document.getElementById("issued-badge-lifecycle-panel");
const issuedBadgeLifecycleClose = document.getElementById("issued-badge-lifecycle-close");
const issuedBadgeLifecycleStatus = document.getElementById("issued-badge-lifecycle-status");
const issuedBadgeLifecycleOutput = document.getElementById("issued-badge-lifecycle-output");
const issuedBadgeRevokeForm = document.getElementById("issued-badge-revoke-form");

if (assertionsApiPathPrefix.length === 0) {
  return;
}

const loadAssertionLifecycle = async (assertionId, statusElement, outputElement) => {
  const normalizedAssertionId = typeof assertionId === "string" ? assertionId.trim() : "";

  if (normalizedAssertionId.length === 0) {
    setStatus(statusElement, "Assertion ID is required.", true);
    return null;
  }

  setStatus(statusElement, "Loading lifecycle state...", false);
  setCodeOutput(outputElement, "");

  try {
    const response = await fetch(
      assertionsApiPathPrefix + "/" + encodeURIComponent(normalizedAssertionId) + "/lifecycle",
      {
        method: "GET",
        headers: {
          accept: "application/json",
        },
      },
    );
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      setStatus(statusElement, errorDetailFromPayload(payload), true);
      return null;
    }

    setCodeOutput(outputElement, JSON.stringify(payload, null, 2));
    setStatus(statusElement, "Lifecycle audit loaded for " + normalizedAssertionId + ".", false);
    return payload;
  } catch {
    setStatus(statusElement, "Unable to load lifecycle audit.", true);
    return null;
  }
};

if (issuedBadgeLifecycleClose instanceof HTMLButtonElement) {
  issuedBadgeLifecycleClose.addEventListener("click", () => {
    if (issuedBadgeLifecyclePanel instanceof HTMLElement) {
      issuedBadgeLifecyclePanel.hidden = true;
    }
  });
}

if (
  issuedBadgeRevokeForm instanceof HTMLFormElement &&
  issuedBadgeLifecycleStatus instanceof HTMLElement &&
  issuedBadgeLifecycleOutput instanceof HTMLElement
) {
  const assertionIdField = issuedBadgeRevokeForm.elements.namedItem("assertionId");
  const assertionId =
    assertionIdField instanceof HTMLInputElement ? assertionIdField.value.trim() : "";

  if (assertionId.length > 0) {
    void loadAssertionLifecycle(
      assertionId,
      issuedBadgeLifecycleStatus,
      issuedBadgeLifecycleOutput,
    );
  }
}

document.addEventListener("click", (event) => {
  const target = event.target;

  if (!(target instanceof HTMLElement)) {
    return;
  }

  const menuLink = target.closest("a.ct-admin__action-menu-item");

  if (menuLink instanceof HTMLAnchorElement) {
    menuLink.closest("details")?.removeAttribute("open");
  }
});
