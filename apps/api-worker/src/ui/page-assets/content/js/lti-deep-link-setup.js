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
      return lmsLookupSuperseded();
    }

    const assignmentId = itemSelect.value;
    const workflowStatesUrl =
      apiBase.length === 0 || assignmentId.length === 0
        ? ''
        : apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states';

    const outcome = await lmsHydrateWorkflowStateSelect({
      stateSelect,
      workflowStatesUrl,
      fallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
    });

    if (outcome.status === 'failed') {
      setStatus(container, outcome.message, true);
    }

    return outcome;
  };

  const hydrateGradebookItems = async (container) => {
    const apiBase = container.dataset.ltiGradebookApiBase ?? '';
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');
    const stateSelect = container.querySelector('[data-lti-workflow-state-select]');

    if (!(itemSelect instanceof HTMLSelectElement)) {
      return lmsLookupSuperseded();
    }

    const query = itemQuery instanceof HTMLInputElement ? itemQuery.value.trim() : '';
    const itemsUrl = apiBase + '/gradebook-items';

    setStatus(container, '', false);
    const outcome = await lmsHydrateGradebookItemWorkflowSelects({
      itemSelect,
      stateSelect,
      itemsUrl: apiBase.length === 0 ? '' : itemsUrl,
      query,
      itemFallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
      workflowFallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
      workflowStatesUrlForAssignment: (assignmentId) =>
        assignmentId.length === 0
          ? ''
          : apiBase + '/gradebook-items/' + encodeURIComponent(assignmentId) + '/workflow-states',
    });

    if (outcome.status === 'failed') {
      setStatus(container, outcome.message, true);
    }

    return outcome;
  };

  const bindSetup = (container) => {
    const itemSelect = container.querySelector('[data-lti-gradebook-item-select]');
    const itemQuery = container.querySelector('[data-lti-gradebook-item-query]');

    if (!(itemSelect instanceof HTMLSelectElement)) {
      return;
    }

    const refreshItems = lmsBindDebouncedSearch({
      searchInput: itemQuery,
      onInput: () => hydrateGradebookItems(container),
    });

    itemSelect.addEventListener('change', () => {
      itemSelect.dataset.selectedValue = itemSelect.value;
      lmsRunDetached(() => hydrateWorkflowStates(container));
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
