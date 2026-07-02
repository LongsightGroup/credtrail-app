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
    await lmsHydrateGradebookItemSelect({
      itemSelect,
      itemsUrl,
      query,
      fallbackMessage: 'Sakai gradebook access is unavailable. Manual approval remains available.',
      workflowStatesUrlForAssignment: () => '',
    });
    await hydrateWorkflowStates(container);
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