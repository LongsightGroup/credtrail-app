const lmsGradebookItemLabel = (item) => {
  if (!item || typeof item !== "object") {
    return "Untitled gradebook item";
  }

  const title =
    typeof item.title === "string" && item.title.length > 0
      ? item.title
      : "Untitled gradebook item";
  const itemId = typeof item.assignmentId === "string" ? item.assignmentId : "";
  const points =
    typeof item.pointsPossible === "number" ? " · " + String(item.pointsPossible) + " pts" : "";
  return title + points + (itemId.length > 0 ? " (" + itemId + ")" : "");
};

const lmsGradebookItemLabelByIdentity = new Map();

const lmsGradebookItemIdentity = (itemsUrl, assignmentId) => {
  return itemsUrl + "\n" + assignmentId;
};

const lmsRememberGradebookItemLabels = (itemsUrl, items) => {
  items.forEach((item) => {
    lmsGradebookItemLabelByIdentity.set(
      lmsGradebookItemIdentity(itemsUrl, item.assignmentId),
      lmsGradebookItemLabel(item),
    );
  });
};

const lmsSelectedGradebookItemSnapshots = (itemSelect, itemsUrl, selectedValues) => {
  const snapshots = new Map();

  Array.from(itemSelect.selectedOptions).forEach((option) => {
    if (option.value.length > 0) {
      snapshots.set(option.value, option.textContent ?? option.value);
    }
  });

  selectedValues.forEach((assignmentId) => {
    const cachedLabel = lmsGradebookItemLabelByIdentity.get(
      lmsGradebookItemIdentity(itemsUrl, assignmentId),
    );

    if (cachedLabel !== undefined) {
      snapshots.set(assignmentId, cachedLabel);
    }
  });

  return snapshots;
};

const lmsGradebookItemsWithSavedSelections = (input) => {
  const itemById = new Map(input.items.map((item) => [item.assignmentId, item]));
  const selectedItems = input.selectedValues.map((assignmentId) => {
    const item = itemById.get(assignmentId);

    if (item !== undefined) {
      return item;
    }

    return {
      assignmentId,
      savedLabel: input.selectedSnapshots.get(assignmentId) ?? assignmentId,
    };
  });
  const selectedSet = new Set(input.selectedValues);
  return [...selectedItems, ...input.items.filter((item) => !selectedSet.has(item.assignmentId))];
};

const lmsGradebookItemOptionLabel = (item) => {
  return typeof item.savedLabel === "string" ? item.savedLabel : lmsGradebookItemLabel(item);
};

const lmsLookupComplete = () => ({ status: "complete" });

const lmsLookupSuperseded = () => ({ status: "superseded" });

const lmsLookupFailureMessage = (error, fallbackMessage) => {
  if (error instanceof Error) {
    return error.message;
  }

  return typeof error === "string" && error.length > 0 ? error : fallbackMessage;
};

const lmsLookupFailed = (source, error, fallbackMessage) => ({
  status: "failed",
  source,
  message: lmsLookupFailureMessage(error, fallbackMessage),
});

const lmsReportUnexpectedError = (error) => {
  if (typeof globalThis.reportError === "function") {
    globalThis.reportError(error);
    return;
  }

  window.setTimeout(() => {
    throw error;
  }, 0);
};

const lmsRunDetached = (operation) => {
  try {
    Promise.resolve(operation()).catch(lmsReportUnexpectedError);
  } catch (error) {
    lmsReportUnexpectedError(error);
  }
};

const lmsParseJsonBody = async (response) => {
  try {
    return await response.json();
  } catch {
    return null;
  }
};

const lmsErrorDetailFromPayload = (payload, fallbackMessage) => {
  if (payload && typeof payload === "object" && typeof payload.error === "string") {
    return payload.error;
  }

  return fallbackMessage;
};

const lmsFetchJson = async (url, fallbackMessage, options) => {
  const response = await fetch(url, {
    ...(options && typeof options === "object" ? options : {}),
    cache: "no-store",
    signal: options && options.signal instanceof AbortSignal ? options.signal : undefined,
  });
  const payload = await lmsParseJsonBody(response);

  if (!response.ok) {
    throw new Error(lmsErrorDetailFromPayload(payload, fallbackMessage));
  }

  return payload;
};

const lmsUrlWithSearchQuery = (resourceUrl, query) => {
  const normalizedQuery = query.trim();

  if (resourceUrl.length === 0 || normalizedQuery.length === 0) {
    return resourceUrl;
  }

  const separator = resourceUrl.includes("?") ? "&" : "?";
  return resourceUrl + separator + new URLSearchParams({ q: normalizedQuery }).toString();
};

const lmsRequestControllerByOwner = new WeakMap();

const lmsCancelRequest = (requestOwner) => {
  lmsRequestControllerByOwner.get(requestOwner)?.abort();
  lmsRequestControllerByOwner.delete(requestOwner);
};

const lmsFetchLatestJson = async (requestOwner, url, fallbackMessage, requestOptions) => {
  lmsCancelRequest(requestOwner);
  const controller = new AbortController();
  lmsRequestControllerByOwner.set(requestOwner, controller);

  try {
    const payload = await lmsFetchJson(url, fallbackMessage, {
      ...(requestOptions && typeof requestOptions === "object" ? requestOptions : {}),
      signal: controller.signal,
    });

    if (lmsRequestControllerByOwner.get(requestOwner) !== controller) {
      return lmsLookupSuperseded();
    }

    lmsRequestControllerByOwner.delete(requestOwner);
    return { status: "complete", payload };
  } catch (error) {
    if (controller.signal.aborted) {
      return lmsLookupSuperseded();
    }

    lmsRequestControllerByOwner.delete(requestOwner);
    return {
      status: "failed",
      message: lmsLookupFailureMessage(error, fallbackMessage),
    };
  }
};

const lmsSelectedValuesFromSelect = (select) => {
  return Array.from(select.selectedOptions)
    .map((option) => option.value)
    .filter((value) => value.length > 0);
};

const lmsSelectedValuesFromDataset = (select) => {
  const rawValues = select.dataset.selectedValues ?? select.dataset.selectedValue ?? "";
  return rawValues
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
};

const lmsSelectedValuesForSelect = (select) => {
  const fromDataset = lmsSelectedValuesFromDataset(select);
  return fromDataset.length > 0 ? fromDataset : lmsSelectedValuesFromSelect(select);
};

const lmsSetSelectOptions = (
  select,
  entries,
  emptyLabel,
  selectedValues,
  labelForEntry,
  valueForEntry,
) => {
  const selectedSet = new Set(selectedValues);
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = emptyLabel;
  placeholder.disabled = select.required;
  placeholder.selected = selectedSet.size === 0;
  const options = [placeholder];

  entries.forEach((entry) => {
    const option = document.createElement("option");
    option.value = valueForEntry(entry);
    option.textContent = labelForEntry(entry);
    option.selected = selectedSet.has(option.value);
    options.push(option);
  });

  select.replaceChildren(...options);
};

const lmsSetLookupSelectFailureState = (select, label) => {
  const placeholder = select.options.item(0);

  if (placeholder !== null) {
    placeholder.textContent = label;
  }

  select.disabled = false;
};

const lmsFailSelectLookup = (select, label, source, error, fallbackMessage) => {
  const outcome = lmsLookupFailed(source, error, fallbackMessage);
  lmsSetLookupSelectFailureState(select, label);
  return outcome;
};

const lmsPreselectedWorkflowValues = (states, selectedValues) => {
  if (selectedValues.length > 0) {
    return selectedValues;
  }

  return states
    .filter((state) => state && state.preselected === true && typeof state.value === "string")
    .map((state) => state.value);
};

const lmsHydrateWorkflowStateSelect = async (input) => {
  const { stateSelect, workflowStatesUrl, fallbackMessage } = input;

  if (!(stateSelect instanceof HTMLSelectElement)) {
    throw new TypeError("Workflow-state select is unavailable.");
  }

  if (workflowStatesUrl.length === 0) {
    lmsCancelRequest(stateSelect);
    lmsSetSelectOptions(
      stateSelect,
      [],
      "Select gradebook item first",
      [],
      (state) => state.label,
      (state) => state.value,
    );
    stateSelect.disabled = true;
    return lmsLookupComplete();
  }

  stateSelect.disabled = true;
  const preserved = lmsSelectedValuesForSelect(stateSelect);
  lmsSetSelectOptions(
    stateSelect,
    [],
    "Loading workflow states...",
    preserved,
    (state) => state.label,
    (state) => state.value,
  );
  const result = await lmsFetchLatestJson(
    stateSelect,
    workflowStatesUrl,
    fallbackMessage ?? "Unable to load workflow states.",
  );
  if (result.status === "superseded") {
    return result;
  }

  if (result.status === "failed") {
    return lmsFailSelectLookup(
      stateSelect,
      "Workflow states unavailable",
      "workflow-states",
      result.message,
      fallbackMessage ?? "Unable to load workflow states.",
    );
  }

  const states = lmsParseWorkflowStates(result.payload);

  if (states === null) {
    return lmsFailSelectLookup(
      stateSelect,
      "Workflow states unavailable",
      "workflow-states",
      null,
      fallbackMessage ?? "Unable to load workflow states.",
    );
  }

  const defaults = lmsPreselectedWorkflowValues(states, preserved);
  lmsSetSelectOptions(
    stateSelect,
    states,
    states.length === 0 ? "No workflow states available" : "Select workflow states",
    defaults,
    (state) => state.label,
    (state) => state.value,
  );
  stateSelect.disabled = false;
  return lmsLookupComplete();
};

const lmsHydrateGradebookItemSelect = async (input) => {
  const { itemSelect, itemsUrl, query, fallbackMessage, resolveItemsUrl } = input;

  if (!(itemSelect instanceof HTMLSelectElement)) {
    throw new TypeError("Gradebook-item select is unavailable.");
  }

  if (itemsUrl.length === 0) {
    lmsCancelRequest(itemSelect);
    lmsSetSelectOptions(
      itemSelect,
      [],
      "Select course first",
      [],
      lmsGradebookItemLabel,
      (item) => item.assignmentId,
    );
    itemSelect.disabled = true;
    return lmsLookupComplete();
  }

  const selected = lmsSelectedValuesForSelect(itemSelect);
  const selectedSnapshots = lmsSelectedGradebookItemSnapshots(itemSelect, itemsUrl, selected);
  const setItems = (items, emptyLabel) => {
    lmsSetSelectOptions(
      itemSelect,
      lmsGradebookItemsWithSavedSelections({
        items,
        selectedValues: selected,
        selectedSnapshots,
      }),
      emptyLabel,
      selected,
      lmsGradebookItemOptionLabel,
      (item) => item.assignmentId,
    );
  };
  itemSelect.disabled = true;
  setItems([], "Loading gradebook items...");
  const url = lmsUrlWithSearchQuery(itemsUrl, query);
  const result = await lmsFetchLatestJson(
    itemSelect,
    url,
    fallbackMessage ?? "Unable to load gradebook items.",
  );
  if (result.status === "superseded") {
    return result;
  }

  if (result.status === "failed") {
    const outcome = lmsFailSelectLookup(
      itemSelect,
      "Gradebook items unavailable",
      "gradebook-items",
      result.message,
      fallbackMessage ?? "Unable to load gradebook items.",
    );
    return selected.length === 0
      ? outcome
      : {
          ...outcome,
          message: outcome.message + " The saved gradebook item remains selected.",
        };
  }

  const items = lmsParseGradebookItems(result.payload);

  if (items === null) {
    const outcome = lmsFailSelectLookup(
      itemSelect,
      "Gradebook items unavailable",
      "gradebook-items",
      null,
      fallbackMessage ?? "Unable to load gradebook items.",
    );
    return selected.length === 0
      ? outcome
      : {
          ...outcome,
          message: outcome.message + " The saved gradebook item remains selected.",
        };
  }

  lmsRememberGradebookItemLabels(itemsUrl, items);
  const discoveredItemIds = new Set(items.map((item) => item.assignmentId));
  const unresolvedAssignmentIds = selected.filter(
    (assignmentId) => !discoveredItemIds.has(assignmentId),
  );
  let resolvedItems = [];
  let warningMessage = "";

  if (
    unresolvedAssignmentIds.length > 0 &&
    typeof resolveItemsUrl === "string" &&
    resolveItemsUrl.length > 0
  ) {
    const resolution = await lmsFetchLatestJson(
      itemSelect,
      resolveItemsUrl,
      "Unable to restore the saved gradebook item.",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ assignmentIds: unresolvedAssignmentIds }),
      },
    );

    if (resolution.status === "superseded") {
      return resolution;
    }

    if (resolution.status === "failed") {
      warningMessage = resolution.message + " The saved gradebook item remains selected.";
    } else {
      const parsedResolution = lmsParseGradebookItems(resolution.payload);

      if (parsedResolution === null) {
        warningMessage =
          "Unable to restore the saved gradebook item name. The saved item remains selected.";
      } else {
        resolvedItems = parsedResolution;
        lmsRememberGradebookItemLabels(itemsUrl, resolvedItems);
        const resolvedItemIds = new Set(resolvedItems.map((item) => item.assignmentId));

        if (unresolvedAssignmentIds.some((assignmentId) => !resolvedItemIds.has(assignmentId))) {
          warningMessage =
            "The LMS no longer returns the saved gradebook item. Its saved ID remains selected.";
        }
      }
    }
  }

  const combinedItems = [...resolvedItems, ...items];
  setItems(
    combinedItems,
    items.length === 0 ? "No matching gradebook items" : "Select gradebook item",
  );
  itemSelect.disabled = false;
  itemSelect.dataset.selectedValue = selected[0] ?? "";
  itemSelect.dataset.selectedValues = selected.join(",");

  return warningMessage.length === 0
    ? lmsLookupComplete()
    : { status: "complete", warningMessage };
};

const lmsHydrateGradebookItemWorkflowSelects = async (input) => {
  const {
    itemSelect,
    stateSelect,
    itemsUrl,
    query,
    itemFallbackMessage,
    workflowFallbackMessage,
    workflowStatesUrlForAssignment,
  } = input;
  const [itemOutcome, stateClearingOutcome] = await Promise.all([
    lmsHydrateGradebookItemSelect({
      itemSelect,
      itemsUrl,
      query,
      fallbackMessage: itemFallbackMessage,
      resolveItemsUrl: input.resolveItemsUrl,
    }),
    lmsHydrateWorkflowStateSelect({
      stateSelect,
      workflowStatesUrl: "",
      fallbackMessage: workflowFallbackMessage,
    }),
  ]);

  if (stateClearingOutcome.status !== "complete") {
    return stateClearingOutcome;
  }

  if (itemOutcome.status !== "complete" || itemsUrl.length === 0) {
    return itemOutcome;
  }

  const workflowOutcome = await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesUrlForAssignment(itemSelect.value),
    fallbackMessage: workflowFallbackMessage,
  });

  return workflowOutcome.status === "complete" && itemOutcome.warningMessage !== undefined
    ? itemOutcome
    : workflowOutcome;
};

const lmsBindDebouncedSearch = (input) => {
  const { onInput, searchInput, debounceMs } = input;
  let timer = 0;

  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      lmsRunDetached(onInput);
    }, debounceMs ?? 180);
  };

  if (searchInput instanceof HTMLInputElement) {
    searchInput.addEventListener("input", schedule);
  }

  return schedule;
};
