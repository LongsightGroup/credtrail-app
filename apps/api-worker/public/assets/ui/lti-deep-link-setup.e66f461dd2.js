(() => {
  const parseJsonBody = async (response) => {
    try {
      return await response.json();
    } catch {
      return null;
    }
  };

  const errorDetailFromPayload = (payload) => {
    if (payload && typeof payload === 'object' && typeof payload.error === 'string') {
      return payload.error;
    }

    return 'Sakai gradebook access is unavailable. Manual approval remains available.';
  };

  const fetchJson = async (url) => {
    const response = await fetch(url);
    const payload = await parseJsonBody(response);

    if (!response.ok) {
      throw new Error(errorDetailFromPayload(payload));
    }

    return payload;
  };

  const gradebookItemLabel = (item) => {
    if (!item || typeof item !== 'object') {
      return 'Untitled gradebook item';
    }

    const title = typeof item.title === 'string' && item.title.length > 0 ? item.title : 'Untitled gradebook item';
    const itemId = typeof item.assignmentId === 'string' ? item.assignmentId : '';
    const points = typeof item.pointsPossible === 'number' ? ' · ' + String(item.pointsPossible) + ' pts' : '';
    return title + points + (itemId.length > 0 ? ' (' + itemId + ')' : '');
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

  const replaceOptions = (select, entries, placeholderLabel, labelForEntry, valueForEntry, selectedValues) => {
    const selectedSet = new Set(selectedValues);
    const placeholder = document.createElement('option');
    placeholder.value = '';
    placeholder.textContent = placeholderLabel;
    placeholder.disabled = true;
    placeholder.selected = selectedSet.size === 0;
    const options = [placeholder];

    entries.forEach((entry) => {
      const option = document.createElement('option');
      option.value = valueForEntry(entry);
      option.textContent = labelForEntry(entry);
      option.selected = selectedSet.has(option.value);
      options.push(option);
    });

    select.replaceChildren(...options);
  };

  const selectedWorkflowValues = (select) => {
    return Array.from(select.selectedOptions)
      .map((option) => option.value)
      .filter((value) => value.length > 0);
  };

  const hydrateWorkflowStates = async (container) => {
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const stateSelect = container.querySelector('[data-lti-workflow-state-select]');
    const workflowBase = container.dataset.ltiWorkflowStatesUrlBase ?? '';

    if (!(itemSelect instanceof HTMLSelectElement) || !(stateSelect instanceof HTMLSelectElement)) {
      return;
    }

    const assignmentId = itemSelect.value;

    if (workflowBase.length === 0 || assignmentId.length === 0) {
      replaceOptions(stateSelect, [], 'Select a gradebook item first', (state) => state.label, (state) => state.value, []);
      stateSelect.disabled = true;
      return;
    }

    stateSelect.disabled = true;
    replaceOptions(stateSelect, [], 'Loading workflow states...', (state) => state.label, (state) => state.value, selectedWorkflowValues(stateSelect));
    const payload = await fetchJson(workflowBase + '/' + encodeURIComponent(assignmentId) + '/workflow-states');
    const states = payload && Array.isArray(payload.states) ? payload.states : [];
    const selectedValues = selectedWorkflowValues(stateSelect);
    const defaults =
      selectedValues.length > 0
        ? selectedValues
        : states
            .filter((state) => state && state.preselected === true && typeof state.value === 'string')
            .map((state) => state.value);
    replaceOptions(stateSelect, states, states.length === 0 ? 'No workflow states available' : 'Select workflow states', (state) => state.label, (state) => state.value, defaults);
    stateSelect.disabled = false;
  };

  const hydrateGradebookItems = async (container) => {
    const itemsUrl = container.dataset.ltiGradebookItemsUrl ?? '';
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');
    const itemHidden = container.querySelector('[data-lti-gradebook-item-hidden]');

    if (!(itemSelect instanceof HTMLSelectElement) || !(itemHidden instanceof HTMLInputElement)) {
      return;
    }

    if (itemsUrl.length === 0) {
      itemSelect.disabled = true;
      itemHidden.value = '';
      return;
    }

    const query = itemQuery instanceof HTMLInputElement ? itemQuery.value.trim() : '';
    const url = query.length === 0 ? itemsUrl : itemsUrl + '?q=' + encodeURIComponent(query);

    setStatus(container, '', false);
    itemSelect.disabled = true;
    replaceOptions(itemSelect, [], 'Loading gradebook items...', gradebookItemLabel, (item) => item.assignmentId, [itemHidden.value]);
    const payload = await fetchJson(url);
    const items = payload && Array.isArray(payload.items) ? payload.items : [];
    replaceOptions(itemSelect, items, items.length === 0 ? 'No matching gradebook items' : 'Select gradebook item', gradebookItemLabel, (item) => item.assignmentId, [itemHidden.value]);
    itemSelect.disabled = false;
    itemHidden.value = itemSelect.value;
    await hydrateWorkflowStates(container);
  };

  const bindSetup = (container) => {
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');
    const itemHidden = container.querySelector('[data-lti-gradebook-item-hidden]');

    if (!(itemSelect instanceof HTMLSelectElement) || !(itemHidden instanceof HTMLInputElement)) {
      return;
    }

    let timer = 0;
    const refreshItems = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        void hydrateGradebookItems(container).catch((error) => {
          const message = error instanceof Error ? error.message : 'Unable to load Sakai gradebook items.';
          itemSelect.disabled = true;
          itemHidden.value = '';
          setStatus(container, message, true);
          void hydrateWorkflowStates(container);
        });
      }, 180);
    };

    itemSelect.addEventListener('change', () => {
      itemHidden.value = itemSelect.value;
      void hydrateWorkflowStates(container).catch((error) => {
        const message = error instanceof Error ? error.message : 'Unable to load workflow states.';
        setStatus(container, message, true);
      });
    });

    if (itemQuery instanceof HTMLInputElement) {
      itemQuery.addEventListener('input', refreshItems);
    }

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