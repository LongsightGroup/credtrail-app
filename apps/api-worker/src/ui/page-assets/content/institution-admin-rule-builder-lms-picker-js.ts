export const INSTITUTION_ADMIN_RULE_BUILDER_LMS_PICKER_JS = `
    const lmsCourseLabel = (course) => {
      if (!course || typeof course !== 'object') {
        return 'Untitled course';
      }

      const title = typeof course.title === 'string' && course.title.length > 0 ? course.title : 'Untitled course';
      const courseCode = typeof course.courseCode === 'string' && course.courseCode.length > 0 ? course.courseCode : '';
      const courseId = typeof course.courseId === 'string' ? course.courseId : '';
      return title + (courseCode.length > 0 ? ' · ' + courseCode : '') + (courseId.length > 0 ? ' (' + courseId + ')' : '');
    };

    const lmsGradebookItemLabel = (item) => {
      if (!item || typeof item !== 'object') {
        return 'Untitled item';
      }

      const title = typeof item.title === 'string' && item.title.length > 0 ? item.title : 'Untitled item';
      const itemId = typeof item.assignmentId === 'string' ? item.assignmentId : '';
      const points = typeof item.pointsPossible === 'number' ? ' · ' + String(item.pointsPossible) + ' pts' : '';
      return title + points + (itemId.length > 0 ? ' (' + itemId + ')' : '');
    };

    const selectedValuesFromDataset = (select) => {
      const rawValues = select.dataset.selectedValues ?? select.dataset.selectedValue ?? '';
      return rawValues
        .split(',')
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
    };

    const setSelectOptions = (select, entries, emptyLabel, selectedValues, labelForEntry, valueForEntry) => {
      const selectedSet = new Set(selectedValues);
      const options = [];
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = emptyLabel;
      placeholder.disabled = select.required;
      placeholder.selected = selectedSet.size === 0;
      options.push(placeholder);

      entries.forEach((entry) => {
        const option = document.createElement('option');
        option.value = valueForEntry(entry);
        option.textContent = labelForEntry(entry);
        option.selected = selectedSet.has(option.value);
        options.push(option);
      });

      select.replaceChildren(...options);
    };

    const fetchLmsJson = async (path) => {
      const response = await fetch(path);
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        throw new Error(errorDetailFromPayload(payload));
      }

      return payload;
    };

    const sakaiSites403Message =
      'Sakai blocked CredTrail from reading your site list (403). Sign in to Sakai with an account that can view the target site and gradebook, copy a fresh SAKAIID session value, then update this LMS connection. If it still fails, ask a Sakai administrator to allow REST API access to Sites and Gradebook.';

    const lmsLookupErrorMessage = (error, fallback) => {
      const message = error instanceof Error ? error.message : fallback;
      const providerKind = getSelectedLmsProviderKind();

      if (
        providerKind === 'sakai' &&
        message.includes('(403)') &&
        message.includes('/api/users/me/sites')
      ) {
        return sakaiSites403Message;
      }

      return message;
    };

    const setLmsLookupStatus = (message, isError) => {
      if (!(ruleBuilderLmsStatus instanceof HTMLElement)) {
        return;
      }

      const messageElement = ruleBuilderLmsStatus.querySelector(
        '[data-rule-builder-lms-status-message]',
      );

      ruleBuilderLmsStatus.hidden = message.length === 0;
      ruleBuilderLmsStatus.dataset.tone = isError ? 'error' : 'info';

      if (messageElement instanceof HTMLElement) {
        messageElement.textContent = message;
      }
    };

    const coursesPath = (query) => {
      const connectionId = getSelectedLmsConnectionId();

      if (connectionId.length === 0) {
        return '';
      }

      const queryString = query.trim();
      const suffix = queryString.length === 0 ? '' : '?q=' + encodeURIComponent(queryString);
      return lmsConnectionsApiPath + '/' + encodeURIComponent(connectionId) + '/courses' + suffix;
    };

    const gradebookItemsPath = (courseId, query) => {
      const connectionId = getSelectedLmsConnectionId();

      if (connectionId.length === 0 || courseId.length === 0) {
        return '';
      }

      const queryString = query.trim();
      const suffix = queryString.length === 0 ? '' : '?q=' + encodeURIComponent(queryString);
      return (
        lmsConnectionsApiPath +
        '/' +
        encodeURIComponent(connectionId) +
        '/courses/' +
        encodeURIComponent(courseId) +
        '/gradebook-items' +
        suffix
      );
    };

    const workflowStatesPath = (courseId, assignmentId) => {
      const connectionId = getSelectedLmsConnectionId();

      if (connectionId.length === 0 || courseId.length === 0 || assignmentId.length === 0) {
        return '';
      }

      return (
        lmsConnectionsApiPath +
        '/' +
        encodeURIComponent(connectionId) +
        '/courses/' +
        encodeURIComponent(courseId) +
        '/gradebook-items/' +
        encodeURIComponent(assignmentId) +
        '/workflow-states'
      );
    };

    const hydrateCourseSelect = async (select, query) => {
      const path = coursesPath(query);

      if (path.length === 0) {
        setSelectOptions(select, [], 'Select an LMS connection first', [], lmsCourseLabel, (course) => course.courseId);
        select.disabled = true;
        return;
      }

      setLmsLookupStatus('', false);
      select.disabled = true;
      setSelectOptions(select, [], 'Loading courses...', selectedValuesFromDataset(select), lmsCourseLabel, (course) => course.courseId);
      const payload = await fetchLmsJson(path);
      const courses = payload && Array.isArray(payload.courses) ? payload.courses : [];
      setSelectOptions(select, courses, courses.length === 0 ? 'No matching courses' : 'Select course', selectedValuesFromDataset(select), lmsCourseLabel, (course) => course.courseId);
      select.disabled = false;
    };

    const hydrateWorkflowStateSelect = async (card) => {
      const courseId = readFieldFromCard(card, 'courseId');
      const assignmentId = readFieldFromCard(card, 'assignmentId');
      const stateSelect = card.querySelector('[data-lms-workflow-state-select]');

      if (!(stateSelect instanceof HTMLSelectElement)) {
        return;
      }

      const path = workflowStatesPath(courseId, assignmentId);

      if (path.length === 0) {
        setSelectOptions(stateSelect, [], 'Select gradebook item first', [], (state) => state.label, (state) => state.value);
        stateSelect.disabled = true;
        return;
      }

      stateSelect.disabled = true;
      const selectedValues = selectedValuesFromDataset(stateSelect);
      const payload = await fetchLmsJson(path);
      const states = payload && Array.isArray(payload.states) ? payload.states : [];
      const defaults =
        selectedValues.length > 0
          ? selectedValues
          : states
              .filter((state) => state && state.preselected === true && typeof state.value === 'string')
              .map((state) => state.value);
      setSelectOptions(stateSelect, states, states.length === 0 ? 'No workflow states available' : 'Select workflow states', defaults, (state) => state.label, (state) => state.value);
      stateSelect.disabled = false;
    };

    const hydrateGradebookItemSelect = async (card, query) => {
      const courseId = readFieldFromCard(card, 'courseId');
      const itemSelect = card.querySelector('[data-lms-gradebook-item-select]');

      if (!(itemSelect instanceof HTMLSelectElement)) {
        return;
      }

      const path = gradebookItemsPath(courseId, query);

      if (path.length === 0) {
        setSelectOptions(itemSelect, [], 'Select course first', [], lmsGradebookItemLabel, (item) => item.assignmentId);
        itemSelect.disabled = true;
        await hydrateWorkflowStateSelect(card);
        return;
      }

      setLmsLookupStatus('', false);
      itemSelect.disabled = true;
      setSelectOptions(itemSelect, [], 'Loading gradebook items...', selectedValuesFromDataset(itemSelect), lmsGradebookItemLabel, (item) => item.assignmentId);
      const payload = await fetchLmsJson(path);
      const items = payload && Array.isArray(payload.items) ? payload.items : [];
      setSelectOptions(itemSelect, items, items.length === 0 ? 'No matching gradebook items' : 'Select gradebook item', selectedValuesFromDataset(itemSelect), lmsGradebookItemLabel, (item) => item.assignmentId);
      itemSelect.disabled = false;
      await hydrateWorkflowStateSelect(card);
    };

    const bindSearchableCourseSelect = (card, fieldName) => {
      const courseSelect = card.querySelector('[data-field="' + fieldName + '"][data-lms-course-select]');
      const courseSearch = card.querySelector('[data-lms-course-query="' + fieldName + '"]');

      if (!(courseSelect instanceof HTMLSelectElement)) {
        return;
      }

      let timer = 0;
      const refresh = () => {
        const query = courseSearch instanceof HTMLInputElement ? courseSearch.value : '';
        window.clearTimeout(timer);
        timer = window.setTimeout(() => {
          void hydrateCourseSelect(courseSelect, query).then(() => {
            syncDefinitionJsonFromBuilder();
            if (fieldName === 'courseId') {
              void hydrateGradebookItemSelect(card, '');
            }
          }).catch((error) => {
            const message = lmsLookupErrorMessage(error, 'Unable to load LMS courses.');
            setLmsLookupStatus(message, true);
            setStatus(ruleCreateStatus, message, true);
          });
        }, 180);
      };

      courseSelect.addEventListener('change', () => {
        courseSelect.dataset.selectedValue = courseSelect.value;
        courseSelect.dataset.selectedValues = Array.from(courseSelect.selectedOptions).map((option) => option.value).join(',');
        if (fieldName === 'courseId') {
          void hydrateGradebookItemSelect(card, '');
        }
      });

      if (courseSearch instanceof HTMLInputElement) {
        courseSearch.addEventListener('input', refresh);
      }

      refresh();
    };

    const bindSearchableGradebookItemSelect = (card) => {
      const itemSelect = card.querySelector('[data-lms-gradebook-item-select]');
      const itemSearch = card.querySelector('[data-lms-gradebook-item-query]');

      if (!(itemSelect instanceof HTMLSelectElement)) {
        return;
      }

      let timer = 0;
      const refresh = () => {
        const query = itemSearch instanceof HTMLInputElement ? itemSearch.value : '';
        window.clearTimeout(timer);
        timer = window.setTimeout(() => {
          void hydrateGradebookItemSelect(card, query).then(() => {
            syncDefinitionJsonFromBuilder();
          }).catch((error) => {
            const message = lmsLookupErrorMessage(error, 'Unable to load gradebook items.');
            setLmsLookupStatus(message, true);
            setStatus(ruleCreateStatus, message, true);
          });
        }, 180);
      };

      itemSelect.addEventListener('change', () => {
        itemSelect.dataset.selectedValue = itemSelect.value;
        void hydrateWorkflowStateSelect(card).then(() => {
          syncDefinitionJsonFromBuilder();
        });
      });

      if (itemSearch instanceof HTMLInputElement) {
        itemSearch.addEventListener('input', refresh);
      }
    };
`;
