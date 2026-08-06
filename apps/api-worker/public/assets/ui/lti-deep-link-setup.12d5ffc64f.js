(() => {
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
    cache: "no-store",
    signal: options && options.signal instanceof AbortSignal ? options.signal : undefined,
  });
  const payload = await lmsParseJsonBody(response);

  if (!response.ok) {
    throw new Error(lmsErrorDetailFromPayload(payload, fallbackMessage));
  }

  return payload;
};

const lmsRequestControllerBySelect = new WeakMap();

const lmsCancelSelectRequest = (select) => {
  lmsRequestControllerBySelect.get(select)?.abort();
  lmsRequestControllerBySelect.delete(select);
};

const lmsFetchLatestSelectJson = async (select, url, fallbackMessage) => {
  lmsCancelSelectRequest(select);
  const controller = new AbortController();
  lmsRequestControllerBySelect.set(select, controller);

  try {
    const payload = await lmsFetchJson(url, fallbackMessage, {
      signal: controller.signal,
    });

    if (lmsRequestControllerBySelect.get(select) !== controller) {
      return { status: "superseded" };
    }

    lmsRequestControllerBySelect.delete(select);
    return { status: "complete", payload };
  } catch (error) {
    if (controller.signal.aborted) {
      return { status: "superseded" };
    }

    lmsRequestControllerBySelect.delete(select);
    throw error;
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
    return false;
  }

  if (workflowStatesUrl.length === 0) {
    lmsCancelSelectRequest(stateSelect);
    lmsSetSelectOptions(
      stateSelect,
      [],
      "Select gradebook item first",
      [],
      (state) => state.label,
      (state) => state.value,
    );
    stateSelect.disabled = true;
    return true;
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
  const result = await lmsFetchLatestSelectJson(
    stateSelect,
    workflowStatesUrl,
    fallbackMessage ?? "Unable to load workflow states.",
  );
  if (result.status === "superseded") {
    return false;
  }

  const payload = result.payload;
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
  return true;
};

const lmsHydrateGradebookItemSelect = async (input) => {
  const { itemSelect, itemsUrl, query, fallbackMessage } = input;

  if (!(itemSelect instanceof HTMLSelectElement)) {
    return false;
  }

  if (itemsUrl.length === 0) {
    lmsCancelSelectRequest(itemSelect);
    lmsSetSelectOptions(
      itemSelect,
      [],
      "Select course first",
      [],
      lmsGradebookItemLabel,
      (item) => item.assignmentId,
    );
    itemSelect.disabled = true;
    return true;
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
  const result = await lmsFetchLatestSelectJson(
    itemSelect,
    url,
    fallbackMessage ?? "Unable to load gradebook items.",
  );
  if (result.status === "superseded") {
    return false;
  }

  const payload = result.payload;
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

  return true;
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
  const itemHydration = lmsHydrateGradebookItemSelect({
    itemSelect,
    itemsUrl,
    query,
    fallbackMessage: itemFallbackMessage,
  });

  await lmsHydrateWorkflowStateSelect({
    stateSelect,
    workflowStatesUrl: "",
    fallbackMessage: workflowFallbackMessage,
  });

  const didHydrateItems = await itemHydration;

  if (!didHydrateItems || itemsUrl.length === 0) {
    return didHydrateItems;
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
      void onInput();
    }, debounceMs ?? 180);
  };

  if (searchInput instanceof HTMLInputElement) {
    searchInput.addEventListener("input", schedule);
  }

  return schedule;
};

  const setStatus = (container, message, isError) => {
    const status = container.querySelector('[data-lti-gradebook-status]');
    const messageElement = container.querySelector('[data-lti-gradebook-status-message]');

    if (!(status instanceof HTMLElement) || !(messageElement instanceof HTMLElement)) {
      return;
    }

    status.hidden = message.length === 0;
    status.dataset.tone = isError ? 'error' : 'info';
    messageElement.textContent = message;
  };

  const hydrateWorkflowStates = async (container) => {
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const stateSelect = container.querySelector('[data-lti-workflow-state-select]');
    const apiBase = container.dataset.ltiGradebookApiBase ?? '';

    if (!(itemSelect instanceof HTMLSelectElement) || !(stateSelect instanceof HTMLSelectElement)) {
      return;
    }

    const assignmentId = itemSelect.value;
    const workflowStatesUrl =
      apiBase.length === 0 || assignmentId.length === 0
        ? ''
        : apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states';

    await lmsHydrateWorkflowStateSelect({
      stateSelect,
      workflowStatesUrl,
      fallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
    });
  };

  const hydrateGradebookItems = async (container) => {
    const apiBase = container.dataset.ltiGradebookApiBase ?? '';
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');
    const stateSelect = container.querySelector('[data-lti-workflow-state-select]');

    if (!(itemSelect instanceof HTMLSelectElement)) {
      return;
    }

    if (apiBase.length === 0) {
      itemSelect.disabled = true;
      itemSelect.value = '';
      return;
    }

    const query = itemQuery instanceof HTMLInputElement ? itemQuery.value.trim() : '';
    const itemsUrl = apiBase + '/gradebook-items';

    setStatus(container, '', false);
    await lmsHydrateGradebookItemWorkflowSelects({
      itemSelect,
      stateSelect,
      itemsUrl,
      query,
      itemFallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
      workflowFallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
      workflowStatesUrlForAssignment: (assignmentId) =>
        assignmentId.length === 0
          ? ''
          : apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states',
    });
  };

  const bindSetup = (container) => {
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');

    if (!(itemSelect instanceof HTMLSelectElement)) {
      return;
    }

    const refreshItems = lmsBindDebouncedSearch({
      searchInput: itemQuery,
      onInput: () =>
        hydrateGradebookItems(container).catch((error) => {
          const message = error instanceof Error ? error.message : 'Unable to load Sakai gradebook items.';
          itemSelect.disabled = true;
          itemSelect.value = '';
          setStatus(container, message, true);
          void hydrateWorkflowStates(container);
        }),
    });

    itemSelect.addEventListener('change', () => {
      itemSelect.dataset.selectedValue = itemSelect.value;
      void hydrateWorkflowStates(container).catch((error) => {
        const message = error instanceof Error ? error.message : 'Unable to load workflow states.';
        setStatus(container, message, true);
      });
    });

    refreshItems();
  };

  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-lti-gradebook-setup]').forEach((container) => {
      if (container instanceof HTMLElement) {
        bindSetup(container);
      }
    });
  });

})();