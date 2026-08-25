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

const lmsLookupComplete = () => ({ status: "complete" });

const lmsLookupSuperseded = () => ({ status: "superseded" });

const lmsLookupFailureMessage = (error, fallbackMessage) => {
  return error instanceof Error ? error.message : fallbackMessage;
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

const lmsFetchLatestJson = async (requestOwner, url, fallbackMessage) => {
  lmsCancelRequest(requestOwner);
  const controller = new AbortController();
  lmsRequestControllerByOwner.set(requestOwner, controller);

  try {
    const payload = await lmsFetchJson(url, fallbackMessage, {
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
    lmsSetLookupSelectFailureState(stateSelect, "Workflow states unavailable");
    return {
      status: "failed",
      source: "workflow-states",
      message: result.message,
    };
  }

  const states = lmsParseWorkflowStates(result.payload);

  if (states === null) {
    const failed = lmsLookupFailed(
      "workflow-states",
      null,
      fallbackMessage ?? "Unable to load workflow states.",
    );
    lmsSetLookupSelectFailureState(stateSelect, "Workflow states unavailable");
    return failed;
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
  const { itemSelect, itemsUrl, query, fallbackMessage } = input;

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
  itemSelect.disabled = true;
  lmsSetSelectOptions(
    itemSelect,
    [],
    "Loading gradebook items...",
    selected,
    lmsGradebookItemLabel,
    (item) => item.assignmentId,
  );
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
    lmsSetLookupSelectFailureState(itemSelect, "Gradebook items unavailable");
    return {
      status: "failed",
      source: "gradebook-items",
      message: result.message,
    };
  }

  const items = lmsParseGradebookItems(result.payload);

  if (items === null) {
    const failed = lmsLookupFailed(
      "gradebook-items",
      null,
      fallbackMessage ?? "Unable to load gradebook items.",
    );
    lmsSetLookupSelectFailureState(itemSelect, "Gradebook items unavailable");
    return failed;
  }

  lmsSetSelectOptions(
    itemSelect,
    items,
    items.length === 0 ? "No matching gradebook items" : "Select gradebook item",
    selected,
    lmsGradebookItemLabel,
    (item) => item.assignmentId,
  );
  itemSelect.disabled = false;
  itemSelect.dataset.selectedValue = itemSelect.value;
  itemSelect.dataset.selectedValues = lmsSelectedValuesFromSelect(itemSelect).join(",");

  return lmsLookupComplete();
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

  return lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: workflowStatesUrlForAssignment(itemSelect.value),
    fallbackMessage: workflowFallbackMessage,
  });
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
