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
