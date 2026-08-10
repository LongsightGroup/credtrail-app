(() => {
const readAdminContext = () => {
  const contextElement = document.getElementById("ct-admin-context");

  if (!(contextElement instanceof HTMLElement)) {
    return null;
  }

  const contextJson =
    contextElement.dataset.contextJson ??
    (contextElement instanceof HTMLScriptElement ? contextElement.textContent : null) ??
    "{}";

  try {
    const parsedContext = JSON.parse(contextJson);

    return parsedContext && typeof parsedContext === "object" ? parsedContext : null;
  } catch {
    return null;
  }
};

const setStatus = (el, text, isError, tone = "info") => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  el.textContent = text;
  el.dataset.tone = isError ? "error" : tone;
};

const parseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const errorDetailFromPayload = (payload) => {
  return payload && typeof payload.error === "string" ? payload.error : "Request failed";
};

const setCodeOutput = (el, value) => {
  if (!(el instanceof HTMLElement)) {
    return;
  }

  if (typeof value !== "string" || value.length === 0) {
    el.hidden = true;
    el.textContent = "";
    return;
  }

  el.hidden = false;
  el.textContent = value;
};

const parsedContext = readAdminContext();

if (!parsedContext) {
  return;
}

const badgeRuleApiPath =
  parsedContext && typeof parsedContext.badgeRuleApiPath === "string"
    ? parsedContext.badgeRuleApiPath
    : "";
const assertionsApiPathPrefix =
  parsedContext && typeof parsedContext.assertionsApiPathPrefix === "string"
    ? parsedContext.assertionsApiPathPrefix
    : "";

const reportingFiltersForm = document.getElementById("reporting-filters-form");
const reportingFiltersStatus = document.getElementById("reporting-filters-status");
const assertionLifecycleViewForm = document.getElementById("assertion-lifecycle-view-form");
const assertionLifecycleViewStatus = document.getElementById("assertion-lifecycle-view-status");
const assertionLifecycleOutput = document.getElementById("assertion-lifecycle-output");
const assertionLifecycleTransitionForm = document.getElementById(
  "assertion-lifecycle-transition-form",
);
const assertionLifecycleTransitionStatus = document.getElementById(
  "assertion-lifecycle-transition-status",
);
const ruleGovernanceForm = document.getElementById("rule-governance-form");
const ruleGovernanceStatus = document.getElementById("rule-governance-status");
const ruleGovernanceOutput = document.getElementById("rule-governance-output");

const fillLifecycleAssertionIdInputs = (assertionId) => {
  if (typeof assertionId !== "string" || assertionId.length === 0) {
    return;
  }

  if (assertionLifecycleViewForm instanceof HTMLFormElement) {
    const lifecycleInput = assertionLifecycleViewForm.elements.namedItem("assertionId");

    if (lifecycleInput instanceof HTMLInputElement) {
      lifecycleInput.value = assertionId;
    }
  }

  if (assertionLifecycleTransitionForm instanceof HTMLFormElement) {
    const transitionInput = assertionLifecycleTransitionForm.elements.namedItem("assertionId");

    if (transitionInput instanceof HTMLInputElement) {
      transitionInput.value = assertionId;
    }
  }
};

const loadAssertionLifecycle = async (
  assertionId,
  statusElement,
  outputElement = assertionLifecycleOutput,
) => {
  const normalizedAssertionId = typeof assertionId === "string" ? assertionId.trim() : "";

  if (normalizedAssertionId.length === 0) {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Assertion ID is required.", true);
    }

    return null;
  }

  if (statusElement instanceof HTMLElement) {
    setStatus(statusElement, "Loading lifecycle state...", false);
  }

  setCodeOutput(outputElement, "");

  try {
    const response = await fetch(
      assertionsApiPathPrefix + "/" + encodeURIComponent(normalizedAssertionId) + "/lifecycle",
    );
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
      }

      return null;
    }

    const state = payload && typeof payload.state === "string" ? payload.state : "unknown";
    const source = payload && typeof payload.source === "string" ? payload.source : "unknown";
    const eventCount = payload && Array.isArray(payload.events) ? payload.events.length : 0;

    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Lifecycle loaded: state=" +
          state +
          ", source=" +
          source +
          ", events=" +
          String(eventCount) +
          ".",
        false,
      );
    }

    setCodeOutput(outputElement, JSON.stringify(payload, null, 2));
    fillLifecycleAssertionIdInputs(normalizedAssertionId);
    return payload;
  } catch {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Unable to load lifecycle state from this browser session.", true);
    }

    return null;
  }
};
const transitionAssertionLifecycle = async ({
  assertionId,
  toState,
  reasonCode,
  reason,
  statusElement,
}) => {
  const normalizedAssertionId = typeof assertionId === "string" ? assertionId.trim() : "";
  const normalizedToState = typeof toState === "string" ? toState.trim() : "";
  const normalizedReasonCode = typeof reasonCode === "string" ? reasonCode.trim() : "";
  const normalizedReason = typeof reason === "string" ? reason.trim() : "";

  if (
    normalizedAssertionId.length === 0 ||
    normalizedToState.length === 0 ||
    normalizedReasonCode.length === 0
  ) {
    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, "Assertion, target state, and reason code are required.", true);
    }

    return null;
  }

  if (statusElement instanceof HTMLElement) {
    setStatus(statusElement, "Applying lifecycle transition...", false);
  }

  try {
    const response = await fetch(
      assertionsApiPathPrefix +
        "/" +
        encodeURIComponent(normalizedAssertionId) +
        "/lifecycle/transition",
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          toState: normalizedToState,
          reasonCode: normalizedReasonCode,
          ...(normalizedReason.length > 0 ? { reason: normalizedReason } : {}),
        }),
      },
    );
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
      }

      return null;
    }

    const status = payload && typeof payload.status === "string" ? payload.status : "updated";
    const currentState =
      payload && typeof payload.currentState === "string"
        ? payload.currentState
        : normalizedToState;

    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Lifecycle transition result: status=" + status + ", currentState=" + currentState + ".",
        false,
      );
    }

    return payload;
  } catch {
    if (statusElement instanceof HTMLElement) {
      setStatus(
        statusElement,
        "Unable to apply lifecycle transition from this browser session.",
        true,
      );
    }

    return null;
  }
};

const actionMenuGap = 4;
const viewportPadding = 8;
let openActionMenuPopover = null;
let openActionMenuTrigger = null;

const findInlinePanel = (panelId) => {
  if (typeof panelId !== "string" || panelId.length === 0) {
    return null;
  }

  const candidate = document.getElementById(panelId);
  return candidate instanceof HTMLElement ? candidate : null;
};

const findInlinePanelTrigger = (panelId) => {
  if (typeof panelId !== "string" || panelId.length === 0) {
    return null;
  }

  const selector = `[data-admin-inline-panel-trigger="${CSS.escape(panelId)}"]`;
  const candidate = document.querySelector(selector);
  return candidate instanceof HTMLElement ? candidate : null;
};

const openInlinePanel = (trigger, panel) => {
  panel.hidden = false;
  trigger.setAttribute("aria-expanded", "true");
};

const closeInlinePanel = (panel) => {
  panel.hidden = true;

  const trigger = findInlinePanelTrigger(panel.id);
  if (trigger instanceof HTMLElement) {
    trigger.setAttribute("aria-expanded", "false");
    trigger.focus();
  }
};

document.querySelectorAll("[data-admin-inline-panel-trigger]").forEach((trigger) => {
  if (!(trigger instanceof HTMLElement)) {
    return;
  }

  const panelId = trigger.getAttribute("data-admin-inline-panel-trigger") || "";
  const panel = findInlinePanel(panelId);

  if (!(panel instanceof HTMLElement)) {
    return;
  }

  trigger.setAttribute("aria-expanded", panel.hidden ? "false" : "true");
});

const findActionMenuPanel = (trigger) => {
  if (!(trigger instanceof HTMLElement)) {
    return null;
  }

  const menuId = trigger.getAttribute("data-action-menu-trigger") || "";
  if (menuId.length === 0) {
    return null;
  }

  const candidate = document.getElementById(menuId);
  return candidate instanceof HTMLElement ? candidate : null;
};

const positionActionMenuPopover = (popover, trigger) => {
  if (!(popover instanceof HTMLElement) || !(trigger instanceof HTMLElement)) {
    return;
  }

  const triggerRect = trigger.getBoundingClientRect();
  const popoverRect = popover.getBoundingClientRect();
  const popoverWidth = Math.max(popoverRect.width, 0);
  const popoverHeight = Math.max(popoverRect.height, 0);
  const minLeft = viewportPadding;
  const maxLeft = Math.max(minLeft, window.innerWidth - popoverWidth - viewportPadding);
  const preferredLeft = triggerRect.right - popoverWidth;
  const minTop = viewportPadding;
  const maxTop = Math.max(minTop, window.innerHeight - popoverHeight - viewportPadding);
  const belowTop = triggerRect.bottom + actionMenuGap;
  const aboveTop = triggerRect.top - popoverHeight - actionMenuGap;
  const hasBelowSpace = belowTop + popoverHeight <= window.innerHeight - viewportPadding;
  const hasAboveSpace = aboveTop >= viewportPadding;
  const preferredTop = hasBelowSpace || !hasAboveSpace ? belowTop : aboveTop;

  popover.style.position = "fixed";
  popover.style.top = Math.min(Math.max(preferredTop, minTop), maxTop) + "px";
  popover.style.left = Math.min(Math.max(preferredLeft, minLeft), maxLeft) + "px";
  popover.style.right = "auto";
  popover.style.bottom = "auto";
};

const closeOpenActionMenuPopover = () => {
  if (openActionMenuPopover instanceof HTMLElement) {
    openActionMenuPopover.hidden = true;
    openActionMenuPopover.removeAttribute("data-open");
  }

  if (openActionMenuTrigger instanceof HTMLElement) {
    openActionMenuTrigger.setAttribute("aria-expanded", "false");
  }

  openActionMenuPopover = null;
  openActionMenuTrigger = null;
};

const openActionMenu = (trigger, popover) => {
  closeOpenActionMenuPopover();

  popover.hidden = false;
  popover.setAttribute("data-open", "true");
  trigger.setAttribute("aria-expanded", "true");
  openActionMenuPopover = popover;
  openActionMenuTrigger = trigger;
  positionActionMenuPopover(popover, trigger);
};

const toggleActionMenu = (trigger, popover) => {
  if (openActionMenuPopover === popover) {
    closeOpenActionMenuPopover();
    return;
  }

  openActionMenu(trigger, popover);
};

const closeActionMenuPopover = (element) => {
  if (!(element instanceof Element)) {
    return;
  }

  const popover = element.closest(".ct-admin__action-menu-popover");
  if (popover instanceof HTMLElement && popover === openActionMenuPopover) {
    closeOpenActionMenuPopover();
  }
};

document.addEventListener("click", (event) => {
  const target = event.target;

  if (!(target instanceof Element)) {
    return;
  }

  const inlinePanelTrigger = target.closest("[data-admin-inline-panel-trigger]");
  if (inlinePanelTrigger instanceof HTMLElement) {
    const panelId = inlinePanelTrigger.getAttribute("data-admin-inline-panel-trigger") || "";
    const panel = findInlinePanel(panelId);

    if (panel instanceof HTMLElement) {
      event.preventDefault();
      openInlinePanel(inlinePanelTrigger, panel);
    }
    return;
  }

  const inlinePanelClose = target.closest("[data-admin-inline-panel-close]");
  if (inlinePanelClose instanceof HTMLElement) {
    const panelId = inlinePanelClose.getAttribute("data-admin-inline-panel-close") || "";
    const panel = findInlinePanel(panelId);

    if (panel instanceof HTMLElement) {
      event.preventDefault();
      closeInlinePanel(panel);
    }
    return;
  }

  const trigger = target.closest("[data-action-menu-trigger]");
  if (trigger instanceof HTMLElement) {
    const popover = findActionMenuPanel(trigger);
    if (popover instanceof HTMLElement) {
      event.preventDefault();
      event.stopPropagation();
      toggleActionMenu(trigger, popover);
    }
    return;
  }

  if (openActionMenuPopover instanceof HTMLElement && !openActionMenuPopover.contains(target)) {
    closeOpenActionMenuPopover();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeOpenActionMenuPopover();
  }
});

document.addEventListener(
  "scroll",
  () => {
    closeOpenActionMenuPopover();
  },
  { capture: true, passive: true },
);

window.CredTrailAdminActionMenus = {
  close: closeActionMenuPopover,
  position: positionActionMenuPopover,
};

document.querySelectorAll("form[data-confirm-message]").forEach((form) => {
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  form.addEventListener("submit", (event) => {
    const message = form.dataset.confirmMessage ?? "Continue?";

    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
});

let hasAutomaticRoleUpdates = false;

document.querySelectorAll("form[data-admin-role-form]").forEach((form) => {
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const roleSelect = form.querySelector('select[name="role"]');
  const fallbackButton = form.querySelector("[data-admin-role-submit]");

  if (
    !(roleSelect instanceof HTMLSelectElement) ||
    !(fallbackButton instanceof HTMLButtonElement)
  ) {
    return;
  }

  let isSubmitting = false;

  roleSelect.addEventListener("change", () => {
    if (isSubmitting || roleSelect.value === roleSelect.dataset.currentRole) {
      return;
    }

    isSubmitting = true;
    form.requestSubmit();
  });

  fallbackButton.hidden = true;
  hasAutomaticRoleUpdates = true;
});

const automaticRoleUpdateNote = document.querySelector("[data-admin-role-auto-save-note]");

if (hasAutomaticRoleUpdates && automaticRoleUpdateNote instanceof HTMLElement) {
  automaticRoleUpdateNote.hidden = false;
}

if (
  assertionLifecycleViewForm instanceof HTMLFormElement &&
  assertionLifecycleViewStatus instanceof HTMLElement
) {
  assertionLifecycleViewForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(assertionLifecycleViewForm);
    const assertionIdRaw = data.get("assertionId");
    await loadAssertionLifecycle(assertionIdRaw, assertionLifecycleViewStatus);
  });
}

if (
  assertionLifecycleTransitionForm instanceof HTMLFormElement &&
  assertionLifecycleTransitionStatus instanceof HTMLElement
) {
  assertionLifecycleTransitionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(assertionLifecycleTransitionForm);
    const assertionIdRaw = data.get("assertionId");
    const toStateRaw = data.get("toState");
    const reasonCodeRaw = data.get("reasonCode");
    const reasonRaw = data.get("reason");
    await transitionAssertionLifecycle({
      assertionId: assertionIdRaw,
      toState: toStateRaw,
      reasonCode: reasonCodeRaw,
      reason: reasonRaw,
      statusElement: assertionLifecycleTransitionStatus,
    });
  });
}

if (ruleGovernanceForm instanceof HTMLFormElement && ruleGovernanceStatus instanceof HTMLElement) {
  ruleGovernanceForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setStatus(ruleGovernanceStatus, "Loading approval and audit history...", false);
    setCodeOutput(ruleGovernanceOutput, "");
    const data = new FormData(ruleGovernanceForm);
    const ruleIdRaw = data.get("ruleId");
    const auditLimitRaw = data.get("auditLimit");
    const ruleId = typeof ruleIdRaw === "string" ? ruleIdRaw.trim() : "";
    const parsedAuditLimit = Number(typeof auditLimitRaw === "string" ? auditLimitRaw.trim() : "");
    const auditLimit =
      Number.isFinite(parsedAuditLimit) && parsedAuditLimit >= 1 && parsedAuditLimit <= 100
        ? Math.trunc(parsedAuditLimit)
        : 20;
    const ruleSelect = ruleGovernanceForm.elements.namedItem("ruleId");
    const selectedOption =
      ruleSelect instanceof HTMLSelectElement ? ruleSelect.selectedOptions.item(0) : null;
    const versionId = selectedOption?.dataset.versionId?.trim() ?? "";

    if (ruleId.length === 0) {
      setStatus(ruleGovernanceStatus, "Rule selection is required.", true);
      return;
    }

    if (versionId.length === 0) {
      setStatus(ruleGovernanceStatus, "Selected rule has no version context to inspect.", true);
      return;
    }

    const approvalHistoryPath =
      badgeRuleApiPath +
      "/" +
      encodeURIComponent(ruleId) +
      "/versions/" +
      encodeURIComponent(versionId) +
      "/approval-history";
    const auditLogPath =
      badgeRuleApiPath +
      "/" +
      encodeURIComponent(ruleId) +
      "/audit-log?limit=" +
      encodeURIComponent(String(auditLimit));

    try {
      const [approvalResponse, auditResponse] = await Promise.all([
        fetch(approvalHistoryPath),
        fetch(auditLogPath),
      ]);
      const [approvalPayload, auditPayload] = await Promise.all([
        parseJsonBody(approvalResponse),
        parseJsonBody(auditResponse),
      ]);

      if (!approvalResponse.ok) {
        setStatus(ruleGovernanceStatus, errorDetailFromPayload(approvalPayload), true);
        return;
      }

      if (!auditResponse.ok) {
        setStatus(ruleGovernanceStatus, errorDetailFromPayload(auditPayload), true);
        return;
      }

      const currentStep =
        approvalPayload &&
        approvalPayload.approval &&
        approvalPayload.approval.currentStep &&
        typeof approvalPayload.approval.currentStep.stepNumber === "number"
          ? approvalPayload.approval.currentStep.stepNumber
          : null;
      const logCount =
        auditPayload && Array.isArray(auditPayload.logs) ? auditPayload.logs.length : 0;

      setStatus(
        ruleGovernanceStatus,
        "History loaded: current approval step=" +
          (currentStep === null ? "none" : String(currentStep)) +
          ", audit events=" +
          String(logCount) +
          ".",
        false,
      );
      setCodeOutput(
        ruleGovernanceOutput,
        JSON.stringify(
          {
            ruleId,
            versionId,
            approval: approvalPayload?.approval ?? null,
            auditLogs: auditPayload?.logs ?? [],
          },
          null,
          2,
        ),
      );
    } catch {
      setStatus(
        ruleGovernanceStatus,
        "Unable to load approval and audit history from this browser session.",
        true,
      );
    }
  });
}

const sidebarToggle = document.querySelector("[data-sidebar-toggle]");
const sidebar = document.querySelector(".ct-admin-sidebar");

if (sidebarToggle instanceof HTMLElement && sidebar instanceof HTMLElement) {
  sidebarToggle.addEventListener("click", () => {
    sidebar.classList.toggle("ct-admin-sidebar--open");
  });

  document.addEventListener("click", (event) => {
    if (
      sidebar.classList.contains("ct-admin-sidebar--open") &&
      !sidebar.contains(event.target) &&
      event.target !== sidebarToggle
    ) {
      sidebar.classList.remove("ct-admin-sidebar--open");
    }
  });
}


  if (reportingFiltersForm instanceof HTMLFormElement) {
    reportingFiltersForm.addEventListener('submit', () => {
      reportingFiltersForm.dataset.reportingSubmitState = 'pending';
      reportingFiltersForm.setAttribute('aria-busy', 'true');

      if (reportingFiltersStatus instanceof HTMLElement) {
        reportingFiltersStatus.textContent = 'Refreshing this page with your current filters...';
      }

      Array.from(reportingFiltersForm.querySelectorAll('button[type="submit"]')).forEach((candidate) => {
        if (candidate instanceof HTMLButtonElement) {
          candidate.disabled = true;
        }
      });
    });
  }

  const reportingBarGroups = Array.from(document.querySelectorAll('[data-reporting-bar-group]')).filter(
    (candidate) => candidate instanceof HTMLElement,
  );

  for (const group of reportingBarGroups) {
    const barValues = Array.from(group.querySelectorAll('[data-reporting-bar-value]')).filter(
      (candidate) => candidate instanceof HTMLElement,
    );

    if (barValues.length === 0) {
      continue;
    }

    const numericValues = barValues
      .map((candidate) => Number(candidate.getAttribute('data-reporting-bar-value') ?? '0'))
      .filter((value) => Number.isFinite(value) && value >= 0);
    const maxValue =
      numericValues.length === 0 ? 0 : numericValues.reduce((max, value) => Math.max(max, value), 0);

    for (const barValue of barValues) {
      const numericValue = Number(barValue.getAttribute('data-reporting-bar-value') ?? '0');
      const ratio = maxValue > 0 && Number.isFinite(numericValue) ? numericValue / maxValue : 0;

      barValue.style.setProperty('--ct-reporting-bar-ratio', ratio.toFixed(4));
    }
  }

  const reportingFocusSections = Array.from(
    document.querySelectorAll('[data-reporting-focus-section]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusLinks = Array.from(
    document.querySelectorAll('[data-reporting-focus-link]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusSectionsById = new Map(reportingFocusSections.map((section) => [section.id, section]));
  const syncReportingFocusTarget = () => {
    const targetId = window.location.hash.length > 1 ? window.location.hash.slice(1) : '';
    const targetSection = targetId.length > 0 ? reportingFocusSectionsById.get(targetId) : undefined;
    const activeRootTargetId = targetSection?.dataset.reportingFocusRoot ?? '';

    for (const section of reportingFocusSections) {
      const isActive = targetId.length > 0 && section.id === targetId;
      section.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        section.focus({ preventScroll: true });
      }
    }

    for (const link of reportingFocusLinks) {
      const focusTarget = link.dataset.reportingFocusTarget ?? '';
      const isRootLink = link.hasAttribute('data-reporting-root-link');
      const isActive =
        (targetId.length > 0 && focusTarget === targetId) ||
        (isRootLink && activeRootTargetId.length > 0 && focusTarget === activeRootTargetId);

      link.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        link.setAttribute('aria-current', isRootLink ? 'location' : 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    }
  };

  if (reportingFocusSections.length > 0 || reportingFocusLinks.length > 0) {
    syncReportingFocusTarget();
    window.addEventListener('hashchange', syncReportingFocusTarget);
  }
})();