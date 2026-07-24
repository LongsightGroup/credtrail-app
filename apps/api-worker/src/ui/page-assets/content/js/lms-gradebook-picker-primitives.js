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
    signal: options && options.signal instanceof AbortSignal ? options.signal : undefined,
  });
  const payload = await lmsParseJsonBody(response);

  if (!response.ok) {
    throw new Error(lmsErrorDetailFromPayload(payload, fallbackMessage));
  }

  return payload;
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
    return;
  }

  if (workflowStatesUrl.length === 0) {
    lmsSetSelectOptions(
      stateSelect,
      [],
      "Select gradebook item first",
      [],
      (state) => state.label,
      (state) => state.value,
    );
    stateSelect.disabled = true;
    return;
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
  const payload = await lmsFetchJson(
    workflowStatesUrl,
    fallbackMessage ?? "Unable to load workflow states.",
  );
  const states = payload && Array.isArray(payload.states) ? payload.states : [];
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
};

const lmsHydrateGradebookItemSelect = async (input) => {
  const { itemSelect, itemsUrl, query, fallbackMessage, workflowStatesUrlForAssignment } = input;

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return { assignmentId: "", workflowStatesUrl: "" };
  }

  if (itemsUrl.length === 0) {
    lmsSetSelectOptions(
      itemSelect,
      [],
      "Select course first",
      [],
      lmsGradebookItemLabel,
      (item) => item.assignmentId,
    );
    itemSelect.disabled = true;
    return { assignmentId: "", workflowStatesUrl: "" };
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
  const url = query.length === 0 ? itemsUrl : itemsUrl + "?q=" + encodeURIComponent(query);
  const payload = await lmsFetchJson(url, fallbackMessage ?? "Unable to load gradebook items.");
  const items = payload && Array.isArray(payload.items) ? payload.items : [];
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

  const assignmentId = itemSelect.value;
  const workflowStatesUrl =
    typeof workflowStatesUrlForAssignment === "function"
      ? workflowStatesUrlForAssignment(assignmentId)
      : "";

  return { assignmentId, workflowStatesUrl };
};

const lmsBindDebouncedSearch = (input) => {
  const { onInput, searchInput, debounceMs } = input;
  let timer = 0;

  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      void onInput();
    }, debounceMs ?? 180);
  };

  if (searchInput instanceof HTMLInputElement) {
    searchInput.addEventListener("input", schedule);
  }

  return schedule;
};
