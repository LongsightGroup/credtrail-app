const setRuleBuilderDraftStatus = (message, tone) => {
  if (!(ruleBuilderDraftStatus instanceof HTMLElement)) {
    return;
  }

  ruleBuilderDraftStatus.textContent = message;
  if (tone) {
    ruleBuilderDraftStatus.dataset.tone = tone;
  } else {
    delete ruleBuilderDraftStatus.dataset.tone;
  }
};

const currentRuleBuilderStep = () => {
  return ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "metadata";
};

const readRuleBuilderDraftPayload = () => {
  const definitionJson =
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement ? ruleBuilderDefinitionJson.value : "";
  const builderState = {
    rootLogic: getTextFieldValue("rootLogic"),
    issuanceTiming: getTextFieldValue("issuanceTiming"),
    changeSummary: getTextFieldValue("changeSummary"),
    reviewOnMissingFacts:
      getRuleCreateField("reviewOnMissingFacts") instanceof HTMLInputElement
        ? getRuleCreateField("reviewOnMissingFacts").checked
        : false,
    lastTestSummary: ruleBuilderLastTestSummary,
  };

  return {
    target:
      isRuleBuilderEditMode && typeof editRuleContext.latestVersionId === "string"
        ? {
            kind: "formal_rule",
            ruleId: editRuleContext.id,
            versionId: editRuleContext.latestVersionId,
          }
        : { kind: "unfinished" },
    currentStep: currentRuleBuilderStep(),
    name: getTextFieldValue("name"),
    description: getTextFieldValue("description"),
    badgeTemplateId: getTextFieldValue("badgeTemplateId"),
    lmsConnectionId: getTextFieldValue("lmsConnectionId"),
    lmsProviderKind: getTextFieldValue("lmsProviderKind"),
    definitionJson,
    builderState,
  };
};

const performRuleBuilderDraftSave = async (options) => {
  if (ruleBuilderDraftApiPath.length === 0) {
    return false;
  }

  const quiet = options && options.quiet === true;

  if (!quiet) {
    setRuleBuilderDraftStatus("Saving unfinished work...", "info");
  }

  try {
    const response = await fetch(ruleBuilderDraftApiPath, {
      method: "PUT",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(readRuleBuilderDraftPayload()),
    });
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      const message = errorDetailFromPayload(payload);
      setRuleBuilderDraftStatus(message, "error");
      if (!quiet) {
        setStatus(ruleCreateStatus, message, true);
      }
      return false;
    }

    const savedAt =
      payload &&
      payload.draft &&
      typeof payload.draft.updatedAt === "string" &&
      payload.draft.updatedAt.length > 0
        ? new Date(payload.draft.updatedAt).toLocaleTimeString([], {
            hour: "numeric",
            minute: "2-digit",
          })
        : "now";

    setRuleBuilderDraftStatus("Unfinished work saved " + savedAt + ".", "success");

    if (
      !isRuleBuilderEditMode &&
      payload &&
      payload.draft &&
      typeof payload.draft.id === "string"
    ) {
      window.history.replaceState(
        null,
        "",
        rulesListPath +
          "/drafts/" +
          encodeURIComponent(payload.draft.id) +
          "/edit",
      );
    }
    return true;
  } catch {
    const message = "Unable to save this draft from this browser session.";
    setRuleBuilderDraftStatus(message, "error");
    if (!quiet) {
      setStatus(ruleCreateStatus, message, true);
    }
    return false;
  }
};

let ruleBuilderDraftSaveQueue = Promise.resolve(true);

const saveRuleBuilderDraft = (options) => {
  const save = ruleBuilderDraftSaveQueue.then(
    () => performRuleBuilderDraftSave(options),
    () => performRuleBuilderDraftSave(options),
  );
  ruleBuilderDraftSaveQueue = save;
  return save;
};

const persistRuleBuilderDraftOnStepChange = () => {
  setRuleBuilderDraftStatus("Saving unfinished work...", "info");
  void saveRuleBuilderDraft({ quiet: true });
};

const applyBuilderDraftPayload = (draftContext) => {
  const payload = draftContext.payload;

  if (typeof payload.name === "string") {
    setRuleCreateFieldValue("name", payload.name);
  }

  if (typeof payload.description === "string") {
    setRuleCreateFieldValue("description", payload.description);
  }

  if (typeof payload.badgeTemplateId === "string") {
    setRuleCreateFieldValue("badgeTemplateId", payload.badgeTemplateId);
    ruleBuilderBadgeTemplatePicker.sync();
  }

  if (typeof payload.lmsConnectionId === "string") {
    setRuleCreateFieldValue("lmsConnectionId", payload.lmsConnectionId);
    syncSelectedLmsProviderKind();
  }

  if (typeof payload.definitionJson === "string" && payload.definitionJson.trim().length > 0) {
    try {
      const savedDefinition = JSON.parse(payload.definitionJson);
      ruleBuilderDefinitionJson.value = JSON.stringify(savedDefinition, null, 2);
      applyDefinitionToBuilder(savedDefinition, "Saved draft");
    } catch {
      setRuleBuilderDraftStatus("Saved draft requirements could not be restored.", "warning");
    }
  }

  const builderState = payload.builderState;
  if (builderState && typeof builderState === "object" && !Array.isArray(builderState)) {
    if (builderState.rootLogic === "all" || builderState.rootLogic === "any") {
      setRuleBuilderRootLogic(builderState.rootLogic);
    }

    if (typeof builderState.issuanceTiming === "string") {
      setRuleCreateFieldValue("issuanceTiming", builderState.issuanceTiming);
    }

    if (typeof builderState.changeSummary === "string") {
      setRuleCreateFieldValue("changeSummary", builderState.changeSummary);
    }

    const reviewField = getRuleCreateField("reviewOnMissingFacts");
    if (
      reviewField instanceof HTMLInputElement &&
      typeof builderState.reviewOnMissingFacts === "boolean"
    ) {
      reviewField.checked = builderState.reviewOnMissingFacts;
    }

    if (
      typeof builderState.lastTestSummary === "string" &&
      builderState.lastTestSummary.length > 0
    ) {
      ruleBuilderLastTestSummary = builderState.lastTestSummary;
    }
  }

  const currentStep = draftContext.currentStep;
  if (typeof currentStep === "string") {
    const stepIndex = ruleBuilderStepOrder.indexOf(currentStep);
    if (stepIndex >= 0) {
      setBuilderStepState(stepIndex);
    }
  }
};

const restoreBuilderDraftIfApplicable = () => {
  if (builderDraftContext === null) {
    return;
  }

  const restoreStatus =
    typeof builderDraftContext.restoreStatus === "string"
      ? builderDraftContext.restoreStatus
      : "invalid_payload";

  if (restoreStatus === "invalid_payload") {
    setRuleBuilderDraftStatus(
      "Saved draft data could not be restored. Continue from the current rule settings.",
      "warning",
    );
    return;
  }

  if (restoreStatus === "version_mismatch") {
    setRuleBuilderDraftStatus("Saved draft is for a different version and was ignored.", "warning");
    return;
  }

  if (restoreStatus === "stale") {
    setRuleBuilderDraftStatus(
      "Saved draft is older than the current rule version and was ignored.",
      "warning",
    );
    return;
  }

  applyBuilderDraftPayload(builderDraftContext);
  setRuleBuilderDraftStatus("Draft restored from last save.", "success");
};

if (ruleBuilderStepButtons.length > 0) {
  ruleBuilderStepButtons.forEach((candidate) => {
    if (!(candidate instanceof HTMLButtonElement)) {
      return;
    }

    candidate.addEventListener("click", () => {
      const targetStep = candidate.dataset.ruleStepTarget ?? "";
      const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);

      if (targetIndex >= 0) {
        tryNavigateToStep(targetIndex);
      }
    });
  });
}

if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
  ruleBuilderStepNextButton.addEventListener("click", () => {
    const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? "";

    if (!isStepComplete(currentStep)) {
      showStepGateMessage(currentStep);
      return;
    }

    setBuilderStepState(activeRuleBuilderStepIndex + 1);
  });
}

ruleCreateForm.addEventListener("input", () => {
  syncRuleBuilderSummary();
  setRuleBuilderDraftStatus("Unsaved changes.", "warning");
});

ruleCreateForm.addEventListener("change", () => {
  syncRuleBuilderSummary();
  setRuleBuilderDraftStatus("Unsaved changes.", "warning");
});

if (ruleBuilderSaveDraftButton instanceof HTMLButtonElement) {
  ruleBuilderSaveDraftButton.addEventListener("click", () => {
    void saveRuleBuilderDraft({ quiet: false });
  });
}

const reviewOnMissingFactsField = getRuleCreateField("reviewOnMissingFacts");

if (reviewOnMissingFactsField instanceof HTMLInputElement) {
  reviewOnMissingFactsField.addEventListener("change", () => {
    syncDefinitionJsonFromBuilder();
  });
}

if (ruleBuilderAddConditionButton instanceof HTMLButtonElement) {
  ruleBuilderAddConditionButton.addEventListener("click", () => {
    addConditionToCanvas({
      type: "course_completion",
      courseId: getDefaultCourseId() || getCoursePlaceholder(),
      minCompletionPercent: 100,
      negate: false,
    });
  });
}

if (ruleBuilderAddAlternativePathButton instanceof HTMLButtonElement) {
  ruleBuilderAddAlternativePathButton.addEventListener("click", () => {
    setRuleBuilderRootLogic("any");
    addConditionToCanvas({
      type: "grade_threshold",
      courseId: getDefaultCourseId() || getCoursePlaceholder(),
      scoreField: "final_score",
      minScore: 80,
      negate: false,
    });
    syncDefinitionJsonFromBuilder();
    syncRuleBuilderSummary("Alternative earning path added.");
  });
}

if (ruleBuilderRequireEveryRequirementButton instanceof HTMLButtonElement) {
  ruleBuilderRequireEveryRequirementButton.addEventListener("click", () => {
    setRuleBuilderRootLogic("all");
    syncDefinitionJsonFromBuilder();
    syncRuleBuilderSummary("Learner must meet every requirement.");
  });
}

if (ruleBuilderApplyTemplateButton instanceof HTMLButtonElement) {
  ruleBuilderApplyTemplateButton.addEventListener("click", () => {
    applyTemplatePreset();
  });
}

if (ruleBuilderApplyJsonButton instanceof HTMLButtonElement) {
  ruleBuilderApplyJsonButton.addEventListener("click", () => {
    try {
      const definition = parseDefinitionJson();
      applyDefinitionToBuilder(definition, "JSON");
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to apply JSON to builder.",
        true,
      );
    }
  });
}

if (
  ruleBuilderImportJsonButton instanceof HTMLButtonElement &&
  ruleBuilderImportFileInput instanceof HTMLInputElement
) {
  ruleBuilderImportJsonButton.addEventListener("click", () => {
    ruleBuilderImportFileInput.click();
  });

  ruleBuilderImportFileInput.addEventListener("change", async () => {
    const file = ruleBuilderImportFileInput.files?.item(0);

    if (!(file instanceof File)) {
      return;
    }

    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const definition =
        parsed && typeof parsed === "object" && "definition" in parsed
          ? parsed.definition
          : parsed && typeof parsed === "object" && "conditions" in parsed
            ? parsed
            : null;

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "name" in parsed &&
        typeof parsed.name === "string"
      ) {
        setRuleCreateFieldValue("name", parsed.name);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "description" in parsed &&
        typeof parsed.description === "string"
      ) {
        setRuleCreateFieldValue("description", parsed.description);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "badgeTemplateId" in parsed &&
        typeof parsed.badgeTemplateId === "string"
      ) {
        setRuleCreateFieldValue("badgeTemplateId", parsed.badgeTemplateId);
      }

      if (
        parsed !== null &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        "lmsConnectionId" in parsed &&
        typeof parsed.lmsConnectionId === "string"
      ) {
        setRuleCreateFieldValue("lmsConnectionId", parsed.lmsConnectionId);
        syncSelectedLmsProviderKind();
      }

      if (definition === null) {
        throw new Error("Imported JSON must contain definition.conditions or conditions.");
      }

      ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
      applyDefinitionToBuilder(definition, "Imported JSON");
      ruleBuilderImportFileInput.value = "";
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to import JSON.",
        true,
      );
      ruleBuilderImportFileInput.value = "";
    }
  });
}

if (ruleBuilderExportJsonButton instanceof HTMLButtonElement) {
  ruleBuilderExportJsonButton.addEventListener("click", () => {
    try {
      const definition = parseDefinitionJson();
      const payload = {
        name: getTextFieldValue("name"),
        description: getTextFieldValue("description"),
        badgeTemplateId: getTextFieldValue("badgeTemplateId"),
        lmsConnectionId: getTextFieldValue("lmsConnectionId"),
        definition,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      const exportName =
        payload.name.length === 0
          ? "rule-definition.json"
          : payload.name
              .toLowerCase()
              .replace(/[^a-z0-9]+/g, "-")
              .replace(/^-+|-+$/g, "") + ".json";
      anchor.href = url;
      anchor.download = exportName;
      anchor.click();
      URL.revokeObjectURL(url);
      setStatus(ruleCreateStatus, "Rule JSON exported.", false, "success");
      syncRuleBuilderSummary("Rule JSON exported.");
    } catch (error) {
      setStatus(
        ruleCreateStatus,
        error instanceof Error ? error.message : "Unable to export JSON.",
        true,
      );
      syncRuleBuilderSummary(error instanceof Error ? error.message : "Unable to export JSON.");
    }
  });
}

if (
  ruleBuilderCloneLoadButton instanceof HTMLButtonElement &&
  ruleBuilderCloneRuleSelect instanceof HTMLSelectElement
) {
  ruleBuilderCloneLoadButton.addEventListener("click", async () => {
    const ruleId = ruleBuilderCloneRuleSelect.value.trim();

    if (ruleId.length === 0) {
      setStatus(ruleCreateStatus, "Select a rule to copy.", true);
      syncRuleBuilderSummary("Select a rule to copy.");
      return;
    }

    setStatus(ruleCreateStatus, "Copying rule settings...", false);
    syncRuleBuilderSummary("Copying rule settings...");

    try {
      const response = await fetch(badgeRuleApiPath + "/" + encodeURIComponent(ruleId));
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
        syncRuleBuilderSummary(errorDetailFromPayload(payload));
        return;
      }

      const versions = payload && Array.isArray(payload.versions) ? payload.versions : [];
      const latestVersion = versions.slice().sort((left, right) => {
        const leftVersion = typeof left.versionNumber === "number" ? left.versionNumber : 0;
        const rightVersion = typeof right.versionNumber === "number" ? right.versionNumber : 0;
        return rightVersion - leftVersion;
      })[0];
      const snapshot =
        latestVersion &&
        latestVersion.snapshot &&
        typeof latestVersion.snapshot === "object" &&
        !Array.isArray(latestVersion.snapshot)
          ? latestVersion.snapshot
          : null;

      if (snapshot === null || typeof latestVersion.ruleJson !== "string") {
        setStatus(ruleCreateStatus, "Selected rule has no saved settings to copy.", true);
        syncRuleBuilderSummary("Selected rule has no saved settings to copy.");
        return;
      }

      setRuleCreateFieldValue(
        "description",
        typeof snapshot.description === "string" ? snapshot.description : "",
      );

      if (typeof snapshot.badgeTemplateId === "string") {
        setRuleCreateFieldValue("badgeTemplateId", snapshot.badgeTemplateId);
        ruleBuilderBadgeTemplatePicker.sync(true);
      }

      setRuleCreateFieldValue(
        "lmsConnectionId",
        typeof snapshot.lmsConnectionId === "string" ? snapshot.lmsConnectionId : "",
      );
      syncSelectedLmsProviderKind();

      const definition = JSON.parse(latestVersion.ruleJson);
      ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
      applyDefinitionToBuilder(definition, "Copied rule settings");
    } catch {
      setStatus(ruleCreateStatus, "Unable to copy selected rule from this browser session.", true);
      syncRuleBuilderSummary("Unable to copy selected rule from this browser session.");
    }
  });
}
