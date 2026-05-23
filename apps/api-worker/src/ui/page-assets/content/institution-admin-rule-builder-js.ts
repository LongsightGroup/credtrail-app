export const INSTITUTION_ADMIN_RULE_BUILDER_JS = `
(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  const contextJson =
    contextElement.dataset.contextJson ??
    (contextElement instanceof HTMLScriptElement ? contextElement.textContent : null) ??
    '{}';

  let parsedContext;

  try {
    parsedContext = JSON.parse(contextJson);
  } catch {
    return;
  }

  const tenantAdminPath =
    parsedContext && typeof parsedContext.tenantAdminPath === 'string'
      ? parsedContext.tenantAdminPath
      : '';
  const badgeRuleApiPath =
    parsedContext && typeof parsedContext.badgeRuleApiPath === 'string'
      ? parsedContext.badgeRuleApiPath
      : '';
  const badgeRuleValueListApiPath =
    parsedContext && typeof parsedContext.badgeRuleValueListApiPath === 'string'
      ? parsedContext.badgeRuleValueListApiPath
      : '';
  const badgeRulePreviewSimulationApiPath =
    parsedContext && typeof parsedContext.badgeRulePreviewSimulationApiPath === 'string'
      ? parsedContext.badgeRulePreviewSimulationApiPath
      : '';

  if (
    tenantAdminPath.length === 0 ||
    badgeRuleApiPath.length === 0 ||
    badgeRuleValueListApiPath.length === 0 ||
    badgeRulePreviewSimulationApiPath.length === 0
  ) {
    return;
  }

  const ruleCreateForm = document.getElementById('rule-create-form');
  const ruleCreateStatus = document.getElementById('rule-create-status');
  const ruleBuilderConditionList = document.getElementById('rule-builder-condition-list');
  const ruleBuilderConditionCardTemplate = document.getElementById(
    'rule-builder-condition-card-template',
  );
  const ruleBuilderRootLogic = document.getElementById('rule-builder-root-logic');
  const ruleBuilderDefinitionJson = document.getElementById('rule-builder-definition-json');
  const ruleBuilderTemplatePreset = document.getElementById('rule-builder-template-preset');
  const ruleBuilderApplyTemplateButton = document.getElementById('rule-builder-apply-template');
  const ruleBuilderAddConditionButton = document.getElementById('rule-builder-add-condition');
  const ruleBuilderAddAlternativePathButton = document.getElementById(
    'rule-builder-add-alternative-path',
  );
  const ruleBuilderSaveDraftButton = document.getElementById('rule-builder-save-draft');
  const ruleBuilderLoadDraftButton = document.getElementById('rule-builder-load-draft');
  const ruleBuilderExportJsonButton = document.getElementById('rule-builder-export-json');
  const ruleBuilderImportJsonButton = document.getElementById('rule-builder-import-json');
  const ruleBuilderImportFileInput = document.getElementById('rule-builder-import-file');
  const ruleBuilderApplyJsonButton = document.getElementById('rule-builder-apply-json');
  const ruleBuilderCloneRuleSelect = document.getElementById('rule-builder-clone-rule');
  const ruleBuilderCloneLoadButton = document.getElementById('rule-builder-clone-load');
  const ruleBuilderTestButton = document.getElementById('rule-builder-test');
  const ruleBuilderTestPresetSelect = document.getElementById('rule-builder-test-preset');
  const ruleBuilderApplyTestPresetButton = document.getElementById('rule-builder-apply-test-preset');
  const ruleBuilderTestOutput = document.getElementById('rule-builder-test-output');
  const ruleBuilderTestResult = document.getElementById('rule-builder-test-result');
  const ruleBuilderStepPrevButton = document.getElementById('rule-builder-step-prev');
  const ruleBuilderStepNextButton = document.getElementById('rule-builder-step-next');
  const ruleBuilderStepProgress = document.getElementById('rule-builder-step-progress');
  const ruleBuilderStepCallout = document.getElementById('rule-builder-step-callout');
  const ruleBuilderReturnToPatternButton = document.getElementById('rule-builder-return-to-pattern');
  const ruleBuilderNameVisible = document.getElementById('rule-builder-name-visible');
  const ruleBuilderSubmitButton = document.getElementById('rule-builder-submit');
  const ruleBuilderCanvasCount = document.getElementById('rule-builder-canvas-count');
  const ruleBuilderCanvasLogic = document.getElementById('rule-builder-canvas-logic');
  const ruleBuilderConditionEmpty = document.getElementById('rule-builder-condition-empty');
  const ruleBuilderFlowMode = document.getElementById('rule-builder-flow-mode');
  const ruleBuilderFlowEmpty = document.getElementById('rule-builder-flow-empty');
  const ruleBuilderFlowList = document.getElementById('rule-builder-flow-list');
  const ruleBuilderSummaryMessage = document.getElementById('rule-builder-summary-message');
  const ruleBuilderSummaryRuleName = document.getElementById('rule-builder-summary-rule-name');
  const ruleBuilderSummaryConditionCount = document.getElementById(
    'rule-builder-summary-condition-count',
  );
  const ruleBuilderSummaryRootLogic = document.getElementById('rule-builder-summary-root-logic');
  const ruleBuilderSummaryValidity = document.getElementById('rule-builder-summary-validity');
  const ruleBuilderSummaryLastTest = document.getElementById('rule-builder-summary-last-test');
  const ruleBuilderValueListBody = document.getElementById('rule-builder-value-list-body');
  const ruleBuilderSimulateButton = document.getElementById('rule-builder-simulate');
  const ruleBuilderSimulateLimit = document.getElementById('rule-builder-simulate-limit');
  const ruleBuilderSimulateStatus = document.getElementById('rule-builder-simulate-status');
  const ruleBuilderSimulateOutput = document.getElementById('rule-builder-simulate-output');
  const ruleBuilderSourceList = document.getElementById('rule-builder-source-list');
  const ruleBuilderSourceSample = document.getElementById('rule-builder-source-sample');
  const ruleBuilderStepButtons = Array.from(
    document.querySelectorAll('[data-rule-step-target]'),
  ).filter((candidate) => candidate instanceof HTMLButtonElement);
  const ruleValueListBody = null;
  const ruleValueListStatus = null;
  let ruleValueLists = [];

  const setStatus = (el, text, isError, tone = 'info') => {
    el.textContent = text;
    el.dataset.tone = isError ? 'error' : tone;
  };
  const parseJsonBody = async (response) => {
    try {
      return await response.json();
    } catch {
      return null;
    }
  };
  const errorDetailFromPayload = (payload) => {
    return payload && typeof payload.error === 'string' ? payload.error : 'Request failed';
  };
  const setCodeOutput = (el, value) => {
    if (!(el instanceof HTMLElement)) {
      return;
    }

    if (typeof value !== 'string' || value.length === 0) {
      el.hidden = true;
      el.textContent = '';
      return;
    }

    el.hidden = false;
    el.textContent = value;
  };
  const escapeHtml = (value) => {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  };
  function formatRuleValueListKind(kind) {
    if (kind === 'course_ids') {
      return 'Course IDs';
    }

    if (kind === 'badge_template_ids') {
      return 'Badge template IDs';
    }

    return 'Unknown';
  }

  function createEmptyTableRow(colspan, message) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = colspan;
    cell.className = 'ct-admin__empty';
    cell.textContent = message;
    row.appendChild(cell);

    return row;
  }

  function replaceTableBodyRows(body, rows) {
    if (!(body instanceof HTMLElement)) {
      return;
    }

    body.replaceChildren(...rows);
  }

  function setRuleValueListEmptyState(message) {
    const row = createEmptyTableRow(3, message);

    if (ruleValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(ruleValueListBody, [row]);
    }

    if (ruleBuilderValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(ruleBuilderValueListBody, [row.cloneNode(true)]);
    }
  }

  function createRuleValueListRow(valueList) {
    const label =
      valueList && typeof valueList.label === 'string'
        ? valueList.label
        : 'Untitled list';
    const kind =
      valueList && typeof valueList.kind === 'string'
        ? valueList.kind
        : 'unknown';
    const values =
      valueList && Array.isArray(valueList.values) ? valueList.values : [];
    const valueCount = values.length;
    const valueSummary = valueCount === 0 ? 'No values' : values.join(', ');
    const row = document.createElement('tr');
    const labelCell = document.createElement('td');
    const labelStrong = document.createElement('strong');
    const idMeta = document.createElement('div');
    const kindCell = document.createElement('td');
    const valuesCell = document.createElement('td');
    const valuesMeta = document.createElement('div');

    labelStrong.textContent = label;
    idMeta.className = 'ct-admin__meta';
    idMeta.textContent =
      valueList && typeof valueList.id === 'string' ? valueList.id : 'unknown';
    labelCell.append(labelStrong, idMeta);
    kindCell.textContent = formatRuleValueListKind(kind);
    valuesCell.append(document.createTextNode(valueSummary));
    valuesMeta.className = 'ct-admin__meta';
    valuesMeta.textContent =
      String(valueCount) + ' value' + (valueCount === 1 ? '' : 's');
    valuesCell.appendChild(valuesMeta);
    row.append(labelCell, kindCell, valuesCell);

    return row;
  }

  function renderRuleValueListRows() {
    const rows =
      !Array.isArray(ruleValueLists) || ruleValueLists.length === 0
        ? [createEmptyTableRow(3, 'No reusable lists available yet.')]
        : ruleValueLists.map((valueList) => createRuleValueListRow(valueList));

    if (ruleValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(ruleValueListBody, rows);
    }

    if (ruleBuilderValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(
        ruleBuilderValueListBody,
        rows.map((row) => row.cloneNode(true)),
      );
    }
  }

  async function loadRuleValueLists(statusElement, options = {}) {
    const quietSuccess = options && options.quietSuccess === true;

    if (statusElement instanceof HTMLElement && !quietSuccess) {
      setStatus(statusElement, 'Loading reusable lists...', false);
    }

    if (ruleValueListBody instanceof HTMLElement || ruleBuilderValueListBody instanceof HTMLElement) {
      setRuleValueListEmptyState('Loading reusable lists...');
    }

    try {
      const response = await fetch(badgeRuleValueListApiPath);
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        const detail = errorDetailFromPayload(payload);

        if (statusElement instanceof HTMLElement) {
          setStatus(statusElement, detail, true);
        } else if (ruleCreateStatus instanceof HTMLElement) {
          setStatus(ruleCreateStatus, detail, true);
        }

        setRuleValueListEmptyState('Unable to load reusable lists.');
        return [];
      }

      ruleValueLists =
        payload && Array.isArray(payload.valueLists) ? payload.valueLists : [];
      renderRuleValueListRows();

      if (statusElement instanceof HTMLElement && !quietSuccess) {
        setStatus(
          statusElement,
          'Loaded ' +
            String(ruleValueLists.length) +
            ' reusable list' +
            (ruleValueLists.length === 1 ? '' : 's') +
            '.',
          false,
          'success',
        );
      }

      return ruleValueLists;
    } catch {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Unable to load reusable lists from this browser session.', true);
      } else if (ruleCreateStatus instanceof HTMLElement) {
        setStatus(ruleCreateStatus, 'Unable to load reusable lists from this browser session.', true);
      }

      setRuleValueListEmptyState('Unable to load reusable lists.');
      return [];
    }
  }
  if (
    ruleCreateForm instanceof HTMLFormElement &&
    ruleCreateStatus instanceof HTMLElement &&
    ruleBuilderConditionList instanceof HTMLElement &&
    ruleBuilderRootLogic instanceof HTMLInputElement &&
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement
  ) {
    const badgeRulePreviewApiPath = badgeRuleApiPath + '/preview-evaluate';
    const ruleBuilderDraftStorageKey = 'credtrail:rule-builder:' + tenantAdminPath;
    const ruleBuilderContext =
      parsedContext &&
      parsedContext.ruleBuilderContext &&
      typeof parsedContext.ruleBuilderContext === 'object'
        ? parsedContext.ruleBuilderContext
        : null;
    const badgeTemplateCourseMap = new Map();
    const badgeTemplatesContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.badgeTemplates)
        ? ruleBuilderContext.badgeTemplates
        : [];

    badgeTemplatesContext.forEach((entry) => {
      if (entry && typeof entry.id === 'string') {
        badgeTemplateCourseMap.set(
          entry.id,
          typeof entry.defaultCourseId === 'string' && entry.defaultCourseId.length > 0
            ? entry.defaultCourseId
            : null,
        );
      }
    });

    const fallbackCourseId =
      ruleBuilderContext &&
      typeof ruleBuilderContext.fallbackCourseId === 'string' &&
      ruleBuilderContext.fallbackCourseId.length > 0
        ? ruleBuilderContext.fallbackCourseId
        : '';

    const getSelectedBadgeTemplateId = () => {
      return getTextFieldValue('badgeTemplateId');
    };

    const deriveRelatedCourseIds = (courseId, count) => {
      const ids = [courseId];
      const match = courseId.match(/^(.+?)(\\d+)([A-Z]?)$/i);

      if (match) {
        const prefix = match[1];
        const number = Number(match[2]);
        const suffix = match[3] ?? '';

        for (let index = 1; index < count; index += 1) {
          ids.push(prefix + String(number + index) + suffix);
        }

        return ids;
      }

      for (let index = 1; index < count; index += 1) {
        ids.push(courseId + '-' + String(index + 1));
      }

      return ids;
    };

    const getDefaultCourseId = () => {
      const templateId = getSelectedBadgeTemplateId();
      const fromTemplate =
        templateId.length > 0 ? badgeTemplateCourseMap.get(templateId) : null;

      if (typeof fromTemplate === 'string' && fromTemplate.length > 0) {
        return fromTemplate;
      }

      if (fallbackCourseId.length > 0) {
        return fallbackCourseId;
      }

      return '';
    };

    const getCoursePlaceholder = () => {
      const courseId = getDefaultCourseId();

      return courseId.length > 0 ? courseId : 'COURSE_ID';
    };

    const buildDefaultTemplateDefinitions = (courseId) => {
      const primaryCourseId = courseId.length > 0 ? courseId : 'COURSE_ID';
      const programCourseIds = deriveRelatedCourseIds(primaryCourseId, 3);
      const nextCourseId = programCourseIds[1] ?? primaryCourseId + '-2';
      const surveyId = primaryCourseId + '_EXIT_SURVEY';

      return {
        blank: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                requireCompleted: true,
              },
            ],
          },
        },
        course_completion: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                requireCompleted: true,
              },
            ],
          },
        },
        course_and_grade: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                requireCompleted: true,
              },
              {
                type: 'grade_threshold',
                courseId: primaryCourseId,
                scoreField: 'final_score',
                minScore: 80,
              },
            ],
          },
        },
        program_completion: {
          conditions: {
            all: [
              {
                type: 'program_completion',
                courseIds: programCourseIds,
                minimumCompleted: 3,
              },
            ],
          },
        },
        assignment_submission: {
          conditions: {
            all: [
              {
                type: 'assignment_submission',
                courseId: primaryCourseId,
                assignmentId: 'assignment_1',
                requireSubmitted: true,
              },
            ],
          },
        },
        survey_completion: {
          conditions: {
            all: [
              {
                type: 'survey_completion',
                source: 'qualtrics',
                surveyId,
                requireCompleted: true,
              },
            ],
          },
        },
        time_limited: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                requireCompleted: true,
              },
              {
                type: 'time_window',
                notBefore: new Date().toISOString(),
              },
            ],
          },
        },
        custom_field: {
          conditions: {
            all: [
              {
                type: 'custom_field',
                fieldName: 'programStanding',
                operator: 'equals',
                expectedValue: 'eligible',
              },
            ],
          },
        },
        prerequisite_chain: {
          conditions: {
            all: [
              {
                type: 'prerequisite_badge',
                badgeTemplateId: 'badge_template_foundations',
              },
              {
                type: 'course_completion',
                courseId: nextCourseId,
                requireCompleted: true,
              },
            ],
          },
        },
      };
    };
    let runRuleBuilderTest = async () => {};
    const validRoles = new Set(['owner', 'admin', 'issuer', 'viewer']);
    const conditionTypeLabels = {
      course_completion: 'Course completion',
      grade_threshold: 'Grade threshold',
      program_completion: 'Program completion',
      assignment_submission: 'Assignment submission',
      survey_completion: 'Survey completion',
      time_window: 'Time window',
      prerequisite_badge: 'Prerequisite badge',
      custom_field: 'Custom field',
    };
    const getRuleBuilderRootLogic = () => {
      return ruleBuilderRootLogic.value === 'any' ? 'any' : 'all';
    };
    const setRuleBuilderRootLogic = (value) => {
      const normalizedValue = value === 'any' ? 'any' : 'all';

      ruleBuilderRootLogic.value = normalizedValue;
      document.querySelectorAll('[data-rule-builder-root-logic-option]').forEach((candidate) => {
        if (candidate instanceof HTMLInputElement) {
          candidate.checked = candidate.value === normalizedValue;
        }
      });
    };
    const conditionTypeHelpText = {
      course_completion:
        'Learner must have completed a course, with an optional minimum completion percent.',
      grade_threshold:
        'Learner score must meet the configured minimum and/or maximum threshold.',
      program_completion:
        'Learner must complete enough courses in a program or pathway.',
      assignment_submission:
        'Learner must submit an assignment or evidence, with optional score constraints.',
      survey_completion:
        'Learner must complete a required survey, such as an exit survey or attestation.',
      time_window:
        'Badge can only be earned inside the configured date-time window.',
      prerequisite_badge:
        'Learner must already hold a specific prerequisite badge.',
      custom_field:
        'Learner must match an institution-specific field from imported or connected data.',
    };

    function listOptionsMarkup(kind, selectedValue, emptyLabel) {
      const matchingValueLists = ruleValueLists.filter((valueList) => valueList.kind === kind);
      const options = matchingValueLists
        .map((valueList) => {
          const label =
            typeof valueList.label === 'string' && valueList.label.length > 0
              ? valueList.label
              : valueList.id;
          return (
            '<option value="' +
            escapeHtml(valueList.id) +
            '"' +
            (valueList.id === selectedValue ? ' selected' : '') +
            '>' +
            escapeHtml(
              label +
                ' · ' +
                String(Array.isArray(valueList.values) ? valueList.values.length : 0) +
                ' values',
            ) +
            '</option>'
          );
        })
        .join('');

      return (
        '<option value="">' +
        escapeHtml(emptyLabel) +
        '</option>' +
        options
      );
    }

    function syncExclusiveFieldPair(card, valueFieldName, listFieldName) {
      const valueField = card.querySelector('[data-field="' + valueFieldName + '"]');
      const listField = card.querySelector('[data-field="' + listFieldName + '"]');
      const valueFieldText =
        valueField instanceof HTMLInputElement || valueField instanceof HTMLTextAreaElement
          ? valueField.value.trim()
          : '';
      const listFieldText = listField instanceof HTMLSelectElement ? listField.value.trim() : '';

      if (
        !(
          valueField instanceof HTMLInputElement || valueField instanceof HTMLTextAreaElement
        ) ||
        !(listField instanceof HTMLSelectElement)
      ) {
        return;
      }

      if (valueFieldText.length > 0 && listFieldText.length > 0) {
        valueField.disabled = false;
        listField.disabled = false;
        return;
      }

      valueField.disabled = listFieldText.length > 0;
      listField.disabled = valueFieldText.length > 0;
    }

    function bindExclusiveFieldPair(card, valueFieldName, listFieldName) {
      const valueField = card.querySelector('[data-field="' + valueFieldName + '"]');
      const listField = card.querySelector('[data-field="' + listFieldName + '"]');

      if (
        !(
          valueField instanceof HTMLInputElement || valueField instanceof HTMLTextAreaElement
        ) ||
        !(listField instanceof HTMLSelectElement)
      ) {
        return;
      }

      const syncPair = () => {
        syncExclusiveFieldPair(card, valueFieldName, listFieldName);
      };

      valueField.addEventListener('input', syncPair);
      listField.addEventListener('change', syncPair);
      syncPair();
    }


    const getRuleCreateField = (fieldName) => {
      return ruleCreateForm.elements.namedItem(fieldName);
    };

    const getTextFieldValue = (fieldName) => {
      const field = getRuleCreateField(fieldName);

      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
        return field.value.trim();
      }

      if (field instanceof HTMLSelectElement) {
        return field.value.trim();
      }

      return '';
    };

    const getCheckboxFieldValue = (fieldName) => {
      const field = getRuleCreateField(fieldName);
      return field instanceof HTMLInputElement ? field.checked : false;
    };

    const setRuleCreateFieldValue = (fieldName, value) => {
      const field = getRuleCreateField(fieldName);

      if (field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement) {
        field.value = value;
      }

      if (field instanceof HTMLSelectElement) {
        field.value = value;
      }
    };

    let ruleNameManuallyEdited = false;

    const getSelectedOptionLabel = (field) => {
      if (!(field instanceof HTMLSelectElement)) {
        return '';
      }

      const selectedOption = field.selectedOptions[0];

      if (!(selectedOption instanceof HTMLOptionElement)) {
        return '';
      }

      const optionText = selectedOption.textContent?.trim() ?? '';

      if (optionText.length === 0) {
        return '';
      }

      const templateIdSuffixIndex = optionText.lastIndexOf(' (');

      if (templateIdSuffixIndex > 0) {
        return optionText.slice(0, templateIdSuffixIndex).trim();
      }

      return optionText;
    };

    const buildSuggestedRuleName = () => {
      const badgeTitle = getSelectedOptionLabel(getRuleCreateField('badgeTemplateId'));
      const patternLabel = getSelectedOptionLabel(ruleBuilderTemplatePreset);
      const badgeLabel = badgeTitle.length > 0 ? badgeTitle : 'Badge rule';
      const patternName = patternLabel.length > 0 ? patternLabel : 'Awarding rule';

      return badgeLabel + ' \u2013 ' + patternName;
    };

    const syncSuggestedRuleName = () => {
      if (ruleNameManuallyEdited) {
        return;
      }

      const suggestedName = buildSuggestedRuleName();
      setRuleCreateFieldValue('name', suggestedName);

      if (ruleBuilderNameVisible instanceof HTMLInputElement) {
        ruleBuilderNameVisible.value = suggestedName;
      }
    };

    const ruleBuilderStepPanels = Array.from(
      ruleCreateForm.querySelectorAll('[data-rule-step]'),
    ).filter((candidate) => candidate instanceof HTMLElement);
    const ruleBuilderStepOrder = ruleBuilderStepPanels
      .map((candidate) => candidate.dataset.ruleStep ?? '')
      .filter((stepName) => stepName.length > 0);
    const ruleBuilderStepLabels = {
      metadata: 'Awarding pattern',
      conditions: 'Requirements',
      test: 'Test and submit',
    };
    const ruleBuilderStepCallouts = {
      metadata: 'Choose an awarding pattern, badge, and LMS source, then select Continue.',
      conditions: 'Confirm the requirements learners must meet, then select Continue.',
      test: 'Test with a sample learner. When results look right, create the draft.',
    };
    const ruleBuilderStepGateMessages = {
      metadata: 'Choose a badge template and LMS provider before continuing.',
      conditions: 'Add at least one requirement before continuing.',
      test: 'Run a test with a sample learner before creating the draft.',
    };
    let activeRuleBuilderStepIndex = 0;

    const isMetadataStepComplete = () => {
      return (
        getTextFieldValue('name').length > 0 &&
        getTextFieldValue('badgeTemplateId').length > 0 &&
        getTextFieldValue('lmsProviderKind').length > 0
      );
    };

    const isConditionsStepComplete = () => {
      const cardCount = getConditionCards().length;

      if (cardCount === 0) {
        return false;
      }

      const validationErrors = validateConditionCards(false);

      if (validationErrors.length > 0) {
        return false;
      }

      try {
        const definition = readDefinitionFromBuilder(true);
        const rootConditions =
          definition &&
          typeof definition === 'object' &&
          definition.conditions &&
          typeof definition.conditions === 'object'
            ? definition.conditions
            : null;
        const childCount =
          rootConditions !== null && Array.isArray(rootConditions.all)
            ? rootConditions.all.length
            : rootConditions !== null && Array.isArray(rootConditions.any)
              ? rootConditions.any.length
              : cardCount;

        return childCount > 0;
      } catch {
        return false;
      }
    };

    const isTestStepComplete = () => {
      const testReady =
        ruleBuilderLastTestSummary.startsWith('Matched') ||
        ruleBuilderLastTestSummary.startsWith('No match') ||
        ruleBuilderLastTestSummary.startsWith('Review required');
      let reviewReady = getTextFieldValue('issuanceTiming').length > 0;

      try {
        buildApprovalChain(getTextFieldValue('approvalRoles'));
      } catch {
        reviewReady = false;
      }

      return testReady && reviewReady;
    };

    const getRuleBuilderCompletionState = () => {
      return {
        metadata: isMetadataStepComplete(),
        conditions: isConditionsStepComplete(),
        test: isTestStepComplete(),
      };
    };

    const isStepComplete = (stepName) => {
      const completion = getRuleBuilderCompletionState();
      return completion[stepName] === true;
    };

    const getStepGateMessage = (stepName) => {
      if (stepName === 'metadata') {
        const missingLabels = [];

        if (getTextFieldValue('badgeTemplateId').length === 0) {
          missingLabels.push('badge template');
        }

        if (getTextFieldValue('lmsProviderKind').length === 0) {
          missingLabels.push('LMS provider');
        }

        if (missingLabels.length > 0) {
          return 'Choose a ' + missingLabels.join(' and ') + ' before continuing.';
        }
      }

      if (stepName === 'conditions') {
        const cardCount = getConditionCards().length;

        if (cardCount === 0) {
          return 'Add at least one requirement before continuing. Go back to Step 1 to choose a pattern.';
        }

        const validationErrors = validateConditionCards(false);

        if (validationErrors.length > 0) {
          return validationErrors[0];
        }

        try {
          readDefinitionFromBuilder(true);
        } catch (error) {
          return error instanceof Error ? error.message : 'Fix the requirements before continuing.';
        }
      }

      if (stepName === 'test') {
        const testReady =
          ruleBuilderLastTestSummary.startsWith('Matched') ||
          ruleBuilderLastTestSummary.startsWith('No match') ||
          ruleBuilderLastTestSummary.startsWith('Review required');

        if (!testReady) {
          return 'Run a test with a sample learner before creating the draft.';
        }

        if (getTextFieldValue('issuanceTiming').length === 0) {
          return 'Choose when the badge should be issued before creating the draft.';
        }

        try {
          buildApprovalChain(getTextFieldValue('approvalRoles'));
        } catch (error) {
          return error instanceof Error ? error.message : 'Fix approval roles before creating the draft.';
        }
      }

      return ruleBuilderStepGateMessages[stepName] ?? 'Complete this step before continuing.';
    };

    const canNavigateToStep = (targetIndex) => {
      if (targetIndex < 0 || targetIndex >= ruleBuilderStepOrder.length) {
        return false;
      }

      if (targetIndex <= activeRuleBuilderStepIndex) {
        return true;
      }

      const completion = getRuleBuilderCompletionState();

      for (let index = 0; index < targetIndex; index += 1) {
        const stepName = ruleBuilderStepOrder[index] ?? '';

        if (completion[stepName] !== true) {
          return false;
        }
      }

      return true;
    };

    const showStepGateMessage = (stepName) => {
      if (!(ruleBuilderStepCallout instanceof HTMLElement)) {
        return;
      }

      ruleBuilderStepCallout.textContent = getStepGateMessage(stepName);
      ruleBuilderStepCallout.dataset.tone = 'warning';
    };

    const updateStepNavigationState = () => {
      const completion = getRuleBuilderCompletionState();
      const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';
      const currentComplete = completion[currentStep] === true;

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const targetStep = candidate.dataset.ruleStepTarget ?? '';
        const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);
        const reachable = canNavigateToStep(targetIndex);

        candidate.disabled = !reachable;
        candidate.classList.toggle('is-locked', !reachable);
        candidate.setAttribute('aria-disabled', reachable ? 'false' : 'true');
      });

      if (ruleBuilderStepPrevButton instanceof HTMLButtonElement) {
        ruleBuilderStepPrevButton.disabled = activeRuleBuilderStepIndex === 0;
      }

      if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
        const nextStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex + 1] ?? '';
        const nextStepLabel = ruleBuilderStepLabels[nextStep] ?? '';

        ruleBuilderStepNextButton.textContent =
          nextStepLabel.length > 0 ? 'Continue to ' + nextStepLabel : 'Continue';
        ruleBuilderStepNextButton.disabled =
          activeRuleBuilderStepIndex >= ruleBuilderStepOrder.length - 1 || !currentComplete;
      }

      if (ruleBuilderSubmitButton instanceof HTMLButtonElement) {
        ruleBuilderSubmitButton.disabled =
          activeRuleBuilderStepIndex < ruleBuilderStepOrder.length - 1 || !completion.test;
      }

      if (ruleBuilderStepCallout instanceof HTMLElement) {
        if (!currentComplete) {
          ruleBuilderStepCallout.textContent = getStepGateMessage(currentStep);
          ruleBuilderStepCallout.dataset.tone = 'warning';
        } else {
          ruleBuilderStepCallout.textContent =
            ruleBuilderStepCallouts[currentStep] ?? 'Complete this step, then continue.';
          delete ruleBuilderStepCallout.dataset.tone;
        }
      }
    };

    const setBuilderStepState = (requestedIndex) => {
      if (ruleBuilderStepOrder.length === 0) {
        return;
      }

      const nextIndex = Math.min(
        Math.max(requestedIndex, 0),
        ruleBuilderStepOrder.length - 1,
      );
      activeRuleBuilderStepIndex = nextIndex;
      const activeStep = ruleBuilderStepOrder[nextIndex] ?? '';
      const activeStepLabel = ruleBuilderStepLabels[activeStep] ?? 'Step';

      ruleBuilderStepPanels.forEach((panel) => {
        if (!(panel instanceof HTMLElement)) {
          return;
        }

        const isActive = (panel.dataset.ruleStep ?? '') === activeStep;
        panel.hidden = !isActive;
      });

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const isActive = (candidate.dataset.ruleStepTarget ?? '') === activeStep;
        candidate.classList.toggle('is-active', isActive);

        if (isActive) {
          candidate.setAttribute('aria-current', 'step');
        } else {
          candidate.removeAttribute('aria-current');
        }
      });

      syncRuleBuilderStepCompletion();

      if (activeStep === 'test') {
        applyTestFactPreset();
        void runRuleBuilderTest({ auto: true });
      }
    };

    const tryNavigateToStep = (targetIndex) => {
      if (!canNavigateToStep(targetIndex)) {
        for (let index = 0; index < targetIndex; index += 1) {
          const stepName = ruleBuilderStepOrder[index] ?? '';

          if (!isStepComplete(stepName)) {
            showStepGateMessage(stepName);
            break;
          }
        }

        return false;
      }

      setBuilderStepState(targetIndex);
      return true;
    };

    const getConditionCards = () => {
      return Array.from(
        ruleBuilderConditionList.querySelectorAll('.ct-admin__condition-card'),
      ).filter((candidate) => candidate instanceof HTMLElement);
    };

    const readFieldFromCard = (card, fieldName) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        return field.value.trim();
      }

      return '';
    };

    const readCheckboxFromCard = (card, fieldName) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');
      return field instanceof HTMLInputElement ? field.checked : false;
    };

    const setFieldOnCard = (card, fieldName, value) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        field.value = value;
      }
    };

    const setCheckboxOnCard = (card, fieldName, checked) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

      if (field instanceof HTMLInputElement) {
        field.checked = checked;
      }
    };

    const parseNumberInput = (value) => {
      if (value.trim().length === 0) {
        return null;
      }

      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    };

    const parseCsv = (value) => {
      return value
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
    };

    const parseCustomExpectedValue = (value, valueType) => {
      if (valueType === 'number') {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
      }

      if (valueType === 'boolean') {
        const normalized = value.trim().toLowerCase();

        if (normalized === 'true' || normalized === 'yes' || normalized === '1') {
          return true;
        }

        if (normalized === 'false' || normalized === 'no' || normalized === '0') {
          return false;
        }

        return null;
      }

      return value.trim().length > 0 ? value.trim() : null;
    };

    const toDateTimeLocalInput = (isoValue) => {
      if (typeof isoValue !== 'string' || isoValue.length < 16) {
        return '';
      }

      return isoValue.slice(0, 16);
    };

    const toIsoTimestamp = (value) => {
      if (value.length === 0) {
        return undefined;
      }

      const parsed = Date.parse(value);

      if (!Number.isFinite(parsed)) {
        return null;
      }

      return new Date(parsed).toISOString();
    };

    const cloneRuleBuilderConditionCard = () => {
      if (!(ruleBuilderConditionCardTemplate instanceof HTMLTemplateElement)) {
        return null;
      }

      const firstElement = ruleBuilderConditionCardTemplate.content.firstElementChild;

      if (!(firstElement instanceof HTMLElement)) {
        return null;
      }

      const clone = firstElement.cloneNode(true);

      return clone instanceof HTMLElement ? clone : null;
    };

    const updateConditionCardClass = (card, conditionType) => {
      card.classList.remove(
        'ct-admin__condition-card--course_completion',
        'ct-admin__condition-card--grade_threshold',
        'ct-admin__condition-card--program_completion',
        'ct-admin__condition-card--assignment_submission',
        'ct-admin__condition-card--survey_completion',
        'ct-admin__condition-card--time_window',
        'ct-admin__condition-card--prerequisite_badge',
        'ct-admin__condition-card--custom_field',
      );
      card.classList.add('ct-admin__condition-card--' + conditionType);
    };

    const updateConditionPlainSummary = (card) => {
      const summaryElement = card.querySelector('.ct-admin__condition-summary');

      if (!(summaryElement instanceof HTMLElement)) {
        return;
      }

      const typeSelect = card.querySelector('.ct-admin__condition-type');
      const conditionType =
        typeSelect instanceof HTMLSelectElement ? typeSelect.value : 'course_completion';
      const negatePrefix = readCheckboxFromCard(card, 'negate') ? 'Must not: ' : '';

      try {
        const condition = readConditionFromCard(card, false);
        summaryElement.textContent = negatePrefix + formatConditionPlainSummary(condition);
        return;
      } catch {
        summaryElement.textContent =
          negatePrefix + (conditionTypeLabels[conditionType] ?? 'Requirement');
      }
    };

    const formatConditionPlainSummary = (condition) => {
      if (!condition || typeof condition !== 'object' || typeof condition.type !== 'string') {
        return 'Requirement';
      }

      if (condition.type === 'course_completion') {
        const courseLabel =
          typeof condition.courseListId === 'string' && condition.courseListId.length > 0
            ? 'courses from list ' + condition.courseListId
            : typeof condition.courseId === 'string' && condition.courseId.length > 0
              ? condition.courseId
              : 'the course';
        const completionLabel =
          condition.requireCompleted === false ? 'started ' : 'completed ';
        const minPercent =
          typeof condition.minCompletionPercent === 'number'
            ? ' with at least ' + String(condition.minCompletionPercent) + '% completion'
            : '';

        return 'Learner has ' + completionLabel + courseLabel + minPercent;
      }

      if (condition.type === 'grade_threshold') {
        const courseLabel =
          typeof condition.courseListId === 'string' && condition.courseListId.length > 0
            ? 'courses from list ' + condition.courseListId
            : typeof condition.courseId === 'string' && condition.courseId.length > 0
              ? condition.courseId
              : 'the course';
        const scoreField =
          condition.scoreField === 'current_score' ? 'current score' : 'final score';
        const minScore =
          typeof condition.minScore === 'number'
            ? ' at least ' + String(condition.minScore)
            : '';
        const maxScore =
          typeof condition.maxScore === 'number'
            ? ' no more than ' + String(condition.maxScore)
            : '';

        return (
          'Learner ' +
          scoreField +
          ' in ' +
          courseLabel +
          ' is' +
          minScore +
          maxScore
        );
      }

      if (condition.type === 'program_completion') {
        const courseCount = Array.isArray(condition.courseIds) ? condition.courseIds.length : 0;
        const minimumCompleted =
          typeof condition.minimumCompleted === 'number'
            ? condition.minimumCompleted
            : courseCount;

        if (
          typeof condition.courseListId === 'string' &&
          condition.courseListId.length > 0
        ) {
          return (
            'Learner completes at least ' +
            String(minimumCompleted) +
            ' courses from list ' +
            condition.courseListId
          );
        }

        const courseLabel =
          courseCount > 0 ? condition.courseIds.join(', ') : 'required courses';

        return (
          'Learner completes at least ' +
          String(minimumCompleted) +
          ' of: ' +
          courseLabel
        );
      }

      if (condition.type === 'assignment_submission') {
        const courseLabel =
          typeof condition.courseId === 'string' && condition.courseId.length > 0
            ? condition.courseId
            : 'the course';
        const assignmentLabel =
          typeof condition.assignmentId === 'string' && condition.assignmentId.length > 0
            ? condition.assignmentId
            : 'the assignment';
        const minScore =
          typeof condition.minScore === 'number'
            ? ' with score at least ' + String(condition.minScore)
            : '';

        return (
          'Learner submits ' +
          assignmentLabel +
          ' in ' +
          courseLabel +
          minScore
        );
      }

      if (condition.type === 'survey_completion') {
        const surveyLabel =
          typeof condition.surveyId === 'string' && condition.surveyId.length > 0
            ? condition.surveyId
            : 'the required survey';

        return 'Learner completes survey ' + surveyLabel;
      }

      if (condition.type === 'time_window') {
        const notBefore =
          typeof condition.notBefore === 'string' && condition.notBefore.length > 0
            ? ' after ' + condition.notBefore
            : '';
        const notAfter =
          typeof condition.notAfter === 'string' && condition.notAfter.length > 0
            ? ' before ' + condition.notAfter
            : '';

        return 'Badge can only be earned' + notBefore + notAfter;
      }

      if (condition.type === 'prerequisite_badge') {
        const badgeLabel =
          typeof condition.badgeTemplateListId === 'string' &&
          condition.badgeTemplateListId.length > 0
            ? 'badges from list ' + condition.badgeTemplateListId
            : typeof condition.badgeTemplateId === 'string' &&
                condition.badgeTemplateId.length > 0
              ? condition.badgeTemplateId
              : 'a prerequisite badge';

        return 'Learner already holds ' + badgeLabel;
      }

      if (condition.type === 'custom_field') {
        const fieldName =
          typeof condition.fieldName === 'string' && condition.fieldName.length > 0
            ? condition.fieldName
            : 'custom field';
        const expectedValue =
          typeof condition.expectedValue === 'string' && condition.expectedValue.length > 0
            ? condition.expectedValue
            : 'expected value';

        return (
          'Learner ' +
          fieldName +
          ' ' +
          (typeof condition.operator === 'string' ? condition.operator : 'matches') +
          ' ' +
          expectedValue
        );
      }

      return conditionTypeLabels[condition.type] ?? 'Requirement';
    };

    const setConditionResultState = (card, state, detail) => {
      card.classList.remove(
        'ct-admin__condition-card--result-pass',
        'ct-admin__condition-card--result-fail',
        'ct-admin__condition-card--result-review',
        'ct-admin__condition-card--result-idle',
      );
      card.classList.add('ct-admin__condition-card--result-' + state);

      const resultElement = card.querySelector('.ct-admin__condition-result');

      if (resultElement instanceof HTMLElement) {
        resultElement.dataset.state = state;
        resultElement.textContent = detail;
      }
    };

    const renderConditionFields = (card, seed) => {
      const typeSelect = card.querySelector('.ct-admin__condition-type');
      const fieldsContainer = card.querySelector('.ct-admin__condition-fields');

      if (!(typeSelect instanceof HTMLSelectElement) || !(fieldsContainer instanceof HTMLElement)) {
        return;
      }

      const conditionType = typeSelect.value;
      updateConditionCardClass(card, conditionType);
      const coursePlaceholder = getCoursePlaceholder();
      const programCoursePlaceholder = deriveRelatedCourseIds(coursePlaceholder, 3).join(', ');
      const surveyPlaceholder = coursePlaceholder + '_EXIT_SURVEY';

      if (conditionType === 'course_completion') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use single course ID') +
          '</select></label>' +
          '<label>Min completion % (optional)<input type="number" data-field="minCompletionPercent" min="0" max="100" step="0.01" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireCompleted" checked />Require completed</label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'minCompletionPercent',
          typeof seed.minCompletionPercent === 'number' ? String(seed.minCompletionPercent) : '',
        );
        setCheckboxOnCard(
          card,
          'requireCompleted',
          seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
        );
        bindExclusiveFieldPair(card, 'courseId', 'courseListId');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'grade_threshold') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use single course ID') +
          '</select></label>' +
          '<label>Score field<select data-field="scoreField"><option value="final_score">Final score</option><option value="current_score">Current score</option></select></label>' +
          '<label>Min score (optional)<input type="number" data-field="minScore" min="0" max="100" step="0.01" /></label>' +
          '<label>Max score (optional)<input type="number" data-field="maxScore" min="0" max="100" step="0.01" /></label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'scoreField',
          seed.scoreField === 'current_score' ? 'current_score' : 'final_score',
        );
        setFieldOnCard(card, 'minScore', typeof seed.minScore === 'number' ? String(seed.minScore) : '');
        setFieldOnCard(card, 'maxScore', typeof seed.maxScore === 'number' ? String(seed.maxScore) : '');
        bindExclusiveFieldPair(card, 'courseId', 'courseListId');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'program_completion') {
        fieldsContainer.innerHTML =
          '<label>Course IDs (comma separated)<input type="text" data-field="courseIds" placeholder="' +
          programCoursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use explicit course IDs') +
          '</select></label>' +
          '<label>Minimum completed (optional)<input type="number" data-field="minimumCompleted" min="1" max="200" step="1" /></label>';

        setFieldOnCard(
          card,
          'courseIds',
          Array.isArray(seed.courseIds) ? seed.courseIds.join(', ') : '',
        );
        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'minimumCompleted',
          typeof seed.minimumCompleted === 'number' ? String(seed.minimumCompleted) : '',
        );
        bindExclusiveFieldPair(card, 'courseIds', 'courseListId');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'assignment_submission') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Assignment ID<input type="text" data-field="assignmentId" placeholder="assignment_1" /></label>' +
          '<label>Min score (optional)<input type="number" data-field="minScore" min="0" max="100" step="0.01" /></label>' +
          '<label>Workflow states (comma separated, optional)<input type="text" data-field="workflowStates" placeholder="submitted,graded" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireSubmitted" checked />Require submitted</label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
        setFieldOnCard(
          card,
          'assignmentId',
          typeof seed.assignmentId === 'string' ? seed.assignmentId : '',
        );
        setFieldOnCard(card, 'minScore', typeof seed.minScore === 'number' ? String(seed.minScore) : '');
        setFieldOnCard(
          card,
          'workflowStates',
          Array.isArray(seed.workflowStates) ? seed.workflowStates.join(', ') : '',
        );
        setCheckboxOnCard(
          card,
          'requireSubmitted',
          seed.requireSubmitted === undefined ? true : Boolean(seed.requireSubmitted),
        );
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'survey_completion') {
        fieldsContainer.innerHTML =
          '<label>Survey ID<input type="text" data-field="surveyId" placeholder="' +
          surveyPlaceholder +
          '" /></label>' +
          '<label>Source (optional)<input type="text" data-field="source" placeholder="qualtrics" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireCompleted" checked />Require completed</label>';

        setFieldOnCard(
          card,
          'surveyId',
          typeof seed.surveyId === 'string' ? seed.surveyId : '',
        );
        setFieldOnCard(card, 'source', typeof seed.source === 'string' ? seed.source : '');
        setCheckboxOnCard(
          card,
          'requireCompleted',
          seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
        );
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'time_window') {
        fieldsContainer.innerHTML =
          '<label>Not before (optional)<input type="datetime-local" data-field="notBefore" /></label>' +
          '<label>Not after (optional)<input type="datetime-local" data-field="notAfter" /></label>';

        setFieldOnCard(card, 'notBefore', toDateTimeLocalInput(seed.notBefore));
        setFieldOnCard(card, 'notAfter', toDateTimeLocalInput(seed.notAfter));
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'custom_field') {
        const valueType =
          typeof seed.expectedValue === 'number'
            ? 'number'
            : typeof seed.expectedValue === 'boolean'
              ? 'boolean'
              : 'string';
        fieldsContainer.innerHTML =
          '<label>Field name<input type="text" data-field="fieldName" placeholder="programStanding" /></label>' +
          '<label>Operator<select data-field="operator"><option value="equals">Equals</option><option value="not_equals">Does not equal</option><option value="contains">Contains</option><option value="greater_than_or_equal">Greater than or equal</option><option value="less_than_or_equal">Less than or equal</option></select></label>' +
          '<label>Value type<select data-field="expectedValueType"><option value="string">Text</option><option value="number">Number</option><option value="boolean">True/false</option></select></label>' +
          '<label>Expected value<input type="text" data-field="expectedValue" placeholder="eligible" /></label>';

        setFieldOnCard(
          card,
          'fieldName',
          typeof seed.fieldName === 'string' ? seed.fieldName : '',
        );
        setFieldOnCard(
          card,
          'operator',
          typeof seed.operator === 'string' ? seed.operator : 'equals',
        );
        setFieldOnCard(card, 'expectedValueType', valueType);
        setFieldOnCard(
          card,
          'expectedValue',
          seed.expectedValue === undefined ? '' : String(seed.expectedValue),
        );
        updateConditionPlainSummary(card);
        return;
      }

      fieldsContainer.innerHTML =
        '<label>Required badge template ID<input type="text" data-field="badgeTemplateId" placeholder="badge_template_foundations" /></label>' +
        '<label>Reusable badge-template list<select data-field="badgeTemplateListId">' +
        listOptionsMarkup(
          'badge_template_ids',
          typeof seed.badgeTemplateListId === 'string' ? seed.badgeTemplateListId : '',
          'Use single badge template',
        ) +
        '</select></label>';
      setFieldOnCard(
        card,
        'badgeTemplateId',
        typeof seed.badgeTemplateId === 'string' ? seed.badgeTemplateId : '',
      );
      setFieldOnCard(
        card,
        'badgeTemplateListId',
        typeof seed.badgeTemplateListId === 'string' ? seed.badgeTemplateListId : '',
      );
      bindExclusiveFieldPair(card, 'badgeTemplateId', 'badgeTemplateListId');
      updateConditionPlainSummary(card);
    };

    const readConditionFromCard = (card, strict) => {
      const typeSelect = card.querySelector('.ct-admin__condition-type');
      const negate = readCheckboxFromCard(card, 'negate');

      if (!(typeSelect instanceof HTMLSelectElement)) {
        throw new Error('Requirement row is missing a type selection.');
      }

      const conditionType = typeSelect.value;
      let condition = null;

      if (conditionType === 'course_completion') {
        const courseId = readFieldFromCard(card, 'courseId');
        const courseListId = readFieldFromCard(card, 'courseListId');
        const minCompletionPercent = parseNumberInput(readFieldFromCard(card, 'minCompletionPercent'));

        if (strict && courseId.length === 0 && courseListId.length === 0) {
          throw new Error('Course completion requirement needs a course ID or reusable course list.');
        }

        if (strict && courseId.length > 0 && courseListId.length > 0) {
          throw new Error('Course completion requirement can use course ID or reusable course list, not both.');
        }

        condition = {
          type: 'course_completion',
          requireCompleted: readCheckboxFromCard(card, 'requireCompleted'),
          ...(courseListId.length > 0
            ? { courseListId }
            : {
                courseId: courseId.length > 0 ? courseId : 'COURSE_ID',
              }),
        };

        if (minCompletionPercent !== null) {
          condition.minCompletionPercent = minCompletionPercent;
        }
      } else if (conditionType === 'grade_threshold') {
        const courseId = readFieldFromCard(card, 'courseId');
        const courseListId = readFieldFromCard(card, 'courseListId');
        const minScore = parseNumberInput(readFieldFromCard(card, 'minScore'));
        const maxScore = parseNumberInput(readFieldFromCard(card, 'maxScore'));

        if (strict && courseId.length === 0 && courseListId.length === 0) {
          throw new Error('Grade threshold requirement needs a course ID or reusable course list.');
        }

        if (strict && courseId.length > 0 && courseListId.length > 0) {
          throw new Error('Grade threshold requirement can use course ID or reusable course list, not both.');
        }

        if (strict && minScore === null && maxScore === null) {
          throw new Error('Grade threshold requires min score or max score.');
        }

        condition = {
          type: 'grade_threshold',
          scoreField: readFieldFromCard(card, 'scoreField') === 'current_score' ? 'current_score' : 'final_score',
          ...(courseListId.length > 0
            ? { courseListId }
            : {
                courseId: courseId.length > 0 ? courseId : 'COURSE_ID',
              }),
        };

        if (minScore !== null) {
          condition.minScore = minScore;
        }

        if (maxScore !== null) {
          condition.maxScore = maxScore;
        }
      } else if (conditionType === 'program_completion') {
        const courseIds = parseCsv(readFieldFromCard(card, 'courseIds'));
        const courseListId = readFieldFromCard(card, 'courseListId');
        const minimumCompleted = parseNumberInput(readFieldFromCard(card, 'minimumCompleted'));

        if (strict && courseIds.length === 0 && courseListId.length === 0) {
          throw new Error('Program completion requires course IDs or reusable course list.');
        }

        if (strict && courseIds.length > 0 && courseListId.length > 0) {
          throw new Error('Program completion can use explicit course IDs or reusable course list, not both.');
        }

        condition = {
          type: 'program_completion',
          ...(courseListId.length > 0
            ? { courseListId }
            : {
                courseIds: courseIds.length > 0 ? courseIds : ['COURSE_ID'],
              }),
        };

        if (minimumCompleted !== null) {
          condition.minimumCompleted = Math.trunc(minimumCompleted);
        }
      } else if (conditionType === 'assignment_submission') {
        const courseId = readFieldFromCard(card, 'courseId');
        const assignmentId = readFieldFromCard(card, 'assignmentId');
        const minScore = parseNumberInput(readFieldFromCard(card, 'minScore'));
        const workflowStates = parseCsv(readFieldFromCard(card, 'workflowStates'));

        if (strict && courseId.length === 0) {
          throw new Error('Assignment submission requirement needs a course ID.');
        }

        if (strict && assignmentId.length === 0) {
          throw new Error('Assignment submission requirement needs an assignment ID.');
        }

        condition = {
          type: 'assignment_submission',
          courseId: courseId.length > 0 ? courseId : 'COURSE_ID',
          assignmentId: assignmentId.length > 0 ? assignmentId : 'ASSIGNMENT_ID',
          requireSubmitted: readCheckboxFromCard(card, 'requireSubmitted'),
        };

        if (minScore !== null) {
          condition.minScore = minScore;
        }

        if (workflowStates.length > 0) {
          condition.workflowStates = workflowStates;
        }
      } else if (conditionType === 'survey_completion') {
        const surveyId = readFieldFromCard(card, 'surveyId');
        const source = readFieldFromCard(card, 'source');

        if (strict && surveyId.length === 0) {
          throw new Error('Survey completion requirement needs a survey ID.');
        }

        condition = {
          type: 'survey_completion',
          surveyId: surveyId.length > 0 ? surveyId : 'SURVEY_ID',
          requireCompleted: readCheckboxFromCard(card, 'requireCompleted'),
        };

        if (source.length > 0) {
          condition.source = source;
        }
      } else if (conditionType === 'time_window') {
        const notBeforeIso = toIsoTimestamp(readFieldFromCard(card, 'notBefore'));
        const notAfterIso = toIsoTimestamp(readFieldFromCard(card, 'notAfter'));

        if (notBeforeIso === null || notAfterIso === null) {
          throw new Error('Time window condition has an invalid timestamp.');
        }

        if (strict && notBeforeIso === undefined && notAfterIso === undefined) {
          throw new Error('Time window condition requires not before or not after.');
        }

        condition = {
          type: 'time_window',
        };

        if (notBeforeIso !== undefined) {
          condition.notBefore = notBeforeIso;
        }

        if (notAfterIso !== undefined) {
          condition.notAfter = notAfterIso;
        }
      } else if (conditionType === 'custom_field') {
        const fieldName = readFieldFromCard(card, 'fieldName');
        const operator = readFieldFromCard(card, 'operator');
        const expectedValueType = readFieldFromCard(card, 'expectedValueType');
        const expectedValue = parseCustomExpectedValue(
          readFieldFromCard(card, 'expectedValue'),
          expectedValueType,
        );

        if (strict && fieldName.length === 0) {
          throw new Error('Custom field requirement needs a field name.');
        }

        if (strict && expectedValue === null) {
          throw new Error('Custom field requirement needs a valid expected value.');
        }

        condition = {
          type: 'custom_field',
          fieldName: fieldName.length > 0 ? fieldName : 'fieldName',
          operator:
            operator === 'not_equals' ||
            operator === 'contains' ||
            operator === 'greater_than_or_equal' ||
            operator === 'less_than_or_equal'
              ? operator
              : 'equals',
          expectedValue: expectedValue === null ? 'VALUE' : expectedValue,
        };
      } else {
        const badgeTemplateId = readFieldFromCard(card, 'badgeTemplateId');
        const badgeTemplateListId = readFieldFromCard(card, 'badgeTemplateListId');

        if (strict && badgeTemplateId.length === 0 && badgeTemplateListId.length === 0) {
          throw new Error('Prerequisite badge requirement needs a badge template ID or reusable badge list.');
        }

        if (strict && badgeTemplateId.length > 0 && badgeTemplateListId.length > 0) {
          throw new Error('Prerequisite badge requirement can use badge template ID or reusable badge list, not both.');
        }

        condition = {
          type: 'prerequisite_badge',
          ...(badgeTemplateListId.length > 0
            ? { badgeTemplateListId }
            : {
                badgeTemplateId:
                  badgeTemplateId.length > 0 ? badgeTemplateId : 'badge_template_required',
              }),
        };
      }

      return negate ? { not: condition } : condition;
    };

    const readDefinitionFromBuilder = (strict) => {
      const cards = getConditionCards();

      if (cards.length === 0) {
        throw new Error('Add at least one requirement before creating a draft.');
      }

      const conditions = cards.map((card) => readConditionFromCard(card, strict));
      const rootLogic = getRuleBuilderRootLogic();

      const definition = {
        conditions: rootLogic === 'any' ? { any: conditions } : { all: conditions },
      };

      if (getCheckboxFieldValue('reviewOnMissingFacts')) {
        definition.options = {
          reviewOnMissingFacts: true,
        };
      }

      return definition;
    };

    const leafConditionFromCondition = (condition) => {
      if (condition && typeof condition === 'object' && 'not' in condition) {
        const nested = condition.not;
        return nested && typeof nested === 'object' ? nested : condition;
      }

      return condition;
    };

    const conditionLabel = (condition) => {
      const leaf = leafConditionFromCondition(condition);
      const type = leaf && typeof leaf === 'object' && typeof leaf.type === 'string' ? leaf.type : '';
      return conditionTypeLabels[type] ?? 'Requirement';
    };

    const conditionDetail = (condition) => {
      const leaf = leafConditionFromCondition(condition);

      if (leaf === null || typeof leaf !== 'object') {
        return 'Configure requirement details.';
      }

      if (leaf.type === 'course_completion') {
        return 'Course ' + (leaf.courseId ?? leaf.courseListId ?? 'selected') + ' must be complete.';
      }

      if (leaf.type === 'grade_threshold') {
        const parts = [];

        if (leaf.minScore !== undefined) {
          parts.push('min ' + String(leaf.minScore));
        }

        if (leaf.maxScore !== undefined) {
          parts.push('max ' + String(leaf.maxScore));
        }

        return 'Course ' + (leaf.courseId ?? leaf.courseListId ?? 'selected') + ' score ' + (parts.join(', ') || 'threshold');
      }

      if (leaf.type === 'program_completion') {
        return 'Complete ' + String(leaf.minimumCompleted ?? 'all') + ' required courses.';
      }

      if (leaf.type === 'assignment_submission') {
        return 'Assignment ' + leaf.assignmentId + ' in ' + leaf.courseId + ' must satisfy submission rules.';
      }

      if (leaf.type === 'survey_completion') {
        return 'Survey ' + leaf.surveyId + ' must be completed.';
      }

      if (leaf.type === 'time_window') {
        return 'Qualifying activity must fall inside the configured time window.';
      }

      if (leaf.type === 'prerequisite_badge') {
        return 'Requires badge ' + (leaf.badgeTemplateId ?? leaf.badgeTemplateListId ?? 'selected') + '.';
      }

      if (leaf.type === 'custom_field') {
        return leaf.fieldName + ' ' + (leaf.operator ?? 'equals') + ' ' + String(leaf.expectedValue) + '.';
      }

      return 'Configure requirement details.';
    };

    const readConditionsForPreview = () => {
      return getConditionCards()
        .map((card) => {
          try {
            return readConditionFromCard(card, false);
          } catch {
            return null;
          }
        })
        .filter((condition) => condition !== null);
    };

    const selectedBadgeTemplateLabel = () => {
      const field = getRuleCreateField('badgeTemplateId');

      if (!(field instanceof HTMLSelectElement)) {
        return 'selected badge';
      }

      const option = field.selectedOptions.item(0);
      return option === null ? 'selected badge' : option.textContent?.trim() || 'selected badge';
    };

    const renderRuleFlowPreview = () => {
      if (
        !(ruleBuilderFlowList instanceof HTMLOListElement) ||
        !(ruleBuilderFlowEmpty instanceof HTMLElement)
      ) {
        return;
      }

      const conditions = readConditionsForPreview();
      const rootLogic = getRuleBuilderRootLogic();
      const connectorLabel = rootLogic === 'any' ? 'OR' : 'AND';

      ruleBuilderFlowEmpty.hidden = conditions.length > 0;

      if (ruleBuilderFlowMode instanceof HTMLElement) {
        ruleBuilderFlowMode.textContent =
          conditions.length === 0
            ? 'Waiting for requirements.'
            : rootLogic === 'any'
              ? 'Any path can qualify.'
              : 'All requirements must pass.';
      }

      if (conditions.length === 0) {
        ruleBuilderFlowList.innerHTML = '';
        return;
      }

      const conditionItems = conditions
        .map((condition, index) => {
          const leaf = leafConditionFromCondition(condition);
          const type =
            leaf && typeof leaf === 'object' && typeof leaf.type === 'string' ? leaf.type : 'unknown';
          const isNegated = condition && typeof condition === 'object' && 'not' in condition;
          return (
            '<li class="ct-admin__builder-flow-item ct-admin__builder-flow-item--' +
            escapeHtml(type) +
            '">' +
            (index === 0
              ? ''
              : '<span class="ct-admin__builder-flow-connector">' + connectorLabel + '</span>') +
            '<div class="ct-admin__builder-flow-node">' +
            '<span class="ct-admin__builder-flow-kicker">Requirement ' +
            String(index + 1) +
            '</span>' +
            '<strong>' +
            escapeHtml((isNegated ? 'Exclude: ' : '') + conditionLabel(condition)) +
            '</strong>' +
            '<p>' +
            escapeHtml(conditionDetail(condition)) +
            '</p>' +
            '</div>' +
            '</li>'
          );
        })
        .join('');
      const badgeLabel = selectedBadgeTemplateLabel();

      ruleBuilderFlowList.innerHTML =
        conditionItems +
        '<li class="ct-admin__builder-flow-item ct-admin__builder-flow-item--issue">' +
        '<span class="ct-admin__builder-flow-connector">THEN</span>' +
        '<div class="ct-admin__builder-flow-node">' +
        '<span class="ct-admin__builder-flow-kicker">Outcome</span>' +
        '<strong>Issue badge draft</strong>' +
        '<p>' +
        escapeHtml(badgeLabel) +
        '</p>' +
        '</div>' +
        '</li>';
    };

    const addSourceEntry = (entries, key, label, state, detail) => {
      if (!entries.has(key)) {
        entries.set(key, {
          label,
          state,
          details: [],
        });
      }

      const entry = entries.get(key);

      if (entry && !entry.details.includes(detail)) {
        entry.details.push(detail);
      }
    };

    const sourceEntriesForConditions = (conditions) => {
      const entries = new Map();
      const lmsLabel = getTextFieldValue('lmsProviderKind') || 'canvas';

      conditions.forEach((condition) => {
        const leaf = leafConditionFromCondition(condition);

        if (leaf === null || typeof leaf !== 'object') {
          return;
        }

        if (
          leaf.type === 'course_completion' ||
          leaf.type === 'grade_threshold' ||
          leaf.type === 'program_completion'
        ) {
          addSourceEntry(
            entries,
            'lms-gradebook',
            lmsLabel + ' gradebook',
            'Connected or sample',
            conditionDetail(condition),
          );
          return;
        }

        if (leaf.type === 'assignment_submission') {
          addSourceEntry(
            entries,
            'lms-assignments',
            lmsLabel + ' assignments',
            'Connected or sample',
            conditionDetail(condition),
          );
          return;
        }

        if (leaf.type === 'survey_completion') {
          addSourceEntry(
            entries,
            'survey',
            leaf.source === 'qualtrics' ? 'Qualtrics surveys' : 'Survey facts',
            'Sample or connector facts',
            conditionDetail(condition),
          );
          return;
        }

        if (leaf.type === 'prerequisite_badge') {
          addSourceEntry(
            entries,
            'credtrail',
            'CredTrail issued badges',
            'Available',
            conditionDetail(condition),
          );
          return;
        }

        if (leaf.type === 'custom_field') {
          addSourceEntry(
            entries,
            'custom',
            'Institutional fields',
            'Sample or import facts',
            conditionDetail(condition),
          );
          return;
        }

        if (leaf.type === 'time_window') {
          addSourceEntry(
            entries,
            'clock',
            'System clock',
            'Available',
            conditionDetail(condition),
          );
        }
      });

      return Array.from(entries.values());
    };

    const buildSampleFactsPreview = (conditions) => {
      const advancedFactsJson = getTextFieldValue('testFactsJson');

      if (advancedFactsJson.length > 0) {
        try {
          return JSON.stringify(JSON.parse(advancedFactsJson), null, 2);
        } catch {
          return 'Advanced facts JSON is invalid.';
        }
      }

      const learnerId = getTextFieldValue('testLearnerId') || 'canvas:12345';
      const courseId = getTextFieldValue('testCourseId') || getDefaultCourseId() || getCoursePlaceholder();
      const parsedFinalScore = Number(getTextFieldValue('testFinalScore'));
      const finalScore =
        Number.isFinite(parsedFinalScore) && parsedFinalScore >= 0 && parsedFinalScore <= 100
          ? parsedFinalScore
          : 92;
      const facts = {
        grades: [],
        completions: [],
        submissions: [],
        surveyCompletions: [],
        customFields: [],
        earnedBadgeTemplateIds: [],
      };

      conditions.forEach((condition) => {
        const leaf = leafConditionFromCondition(condition);

        if (leaf === null || typeof leaf !== 'object') {
          return;
        }

        if (leaf.type === 'grade_threshold') {
          facts.grades.push({
            courseId: leaf.courseId ?? courseId,
            learnerId,
            finalScore,
          });
          return;
        }

        if (leaf.type === 'course_completion' || leaf.type === 'program_completion') {
          const courseIds = Array.isArray(leaf.courseIds) ? leaf.courseIds : [leaf.courseId ?? courseId];
          courseIds.forEach((entryCourseId) => {
            facts.completions.push({
              courseId: entryCourseId,
              learnerId,
              completed: getCheckboxFieldValue('testCompleted'),
              completionPercent: getCheckboxFieldValue('testCompleted') ? 100 : 0,
            });
          });
          return;
        }

        if (leaf.type === 'assignment_submission') {
          facts.submissions.push({
            courseId: leaf.courseId,
            assignmentId: leaf.assignmentId,
            learnerId,
            score: finalScore,
            workflowState: 'submitted',
            submittedAt: new Date().toISOString(),
          });
          return;
        }

        if (leaf.type === 'survey_completion') {
          facts.surveyCompletions.push({
            surveyId: leaf.surveyId,
            learnerId,
            ...(leaf.source === undefined ? {} : { source: leaf.source }),
            completed: true,
            completedAt: new Date().toISOString(),
          });
          return;
        }

        if (leaf.type === 'custom_field') {
          facts.customFields.push({
            learnerId,
            fieldName: leaf.fieldName,
            value: leaf.expectedValue,
          });
          return;
        }

        if (leaf.type === 'prerequisite_badge') {
          facts.earnedBadgeTemplateIds.push(leaf.badgeTemplateId ?? 'badge_template_foundations');
        }
      });

      return JSON.stringify(facts, null, 2);
    };

    const renderSourceReadiness = () => {
      if (!(ruleBuilderSourceList instanceof HTMLElement)) {
        return;
      }

      const conditions = readConditionsForPreview();
      const entries = sourceEntriesForConditions(conditions);

      if (entries.length === 0) {
        ruleBuilderSourceList.innerHTML =
          '<div><dt>No sources yet</dt><dd>Add requirements to see which facts CredTrail needs.</dd></div>';
        setCodeOutput(ruleBuilderSourceSample, '');
        return;
      }

      ruleBuilderSourceList.innerHTML = entries
        .map((entry) => {
          return (
            '<div>' +
            '<dt>' +
            escapeHtml(entry.label) +
            '</dt>' +
            '<dd><span class="ct-admin__status-pill">' +
            escapeHtml(entry.state) +
            '</span><span>' +
            escapeHtml(entry.details.join(' ')) +
            '</span></dd>' +
            '</div>'
          );
        })
        .join('');
      setCodeOutput(ruleBuilderSourceSample, buildSampleFactsPreview(conditions));
    };

    const validateConditionCards = (updateRows) => {
      const errors = [];

      getConditionCards().forEach((card, index) => {
        try {
          readConditionFromCard(card, true);

          if (updateRows) {
            setConditionResultState(card, 'idle', 'Ready to test.');
          }
        } catch (error) {
          const message =
            error instanceof Error ? error.message : 'Requirement needs attention.';
          errors.push('Requirement ' + String(index + 1) + ': ' + message);

          if (updateRows) {
            setConditionResultState(card, 'fail', message);
          }
        }
      });

      return errors;
    };

    let ruleBuilderLastTestSummary = 'Not run';

    const resetConditionEvaluationResults = () => {
      getConditionCards().forEach((card) => {
        setConditionResultState(card, 'idle', 'Not evaluated yet.');
      });
    };

    const collectLeafEvaluationNodes = (node, output) => {
      if (node === null || typeof node !== 'object') {
        return;
      }

      const children = Array.isArray(node.children) ? node.children : [];

      if (children.length === 0) {
        output.push(node);
        return;
      }

      children.forEach((child) => {
        collectLeafEvaluationNodes(child, output);
      });
    };

    const rootChildrenFromEvaluationTree = (tree) => {
      if (tree === null || typeof tree !== 'object') {
        return [];
      }

      return Array.isArray(tree.children) ? tree.children : [];
    };

    const applyConditionEvaluationResults = (evaluation) => {
      const cards = getConditionCards();

      if (cards.length === 0) {
        return {
          total: 0,
          matched: 0,
        };
      }

      const directChildren = rootChildrenFromEvaluationTree(
        evaluation && typeof evaluation === 'object' ? evaluation.tree : null,
      );
      let mappedNodes = directChildren;

      if (mappedNodes.length !== cards.length) {
        const leafNodes = [];
        collectLeafEvaluationNodes(
          evaluation && typeof evaluation === 'object' ? evaluation.tree : null,
          leafNodes,
        );
        mappedNodes = leafNodes.length === cards.length ? leafNodes : [];
      }

      if (mappedNodes.length !== cards.length) {
        resetConditionEvaluationResults();
        return {
          total: cards.length,
          matched: 0,
        };
      }

      let matchedCount = 0;

      cards.forEach((card, index) => {
        const node = mappedNodes[index];
        const matched = node && typeof node.matched === 'boolean' ? node.matched : null;
        const detail = node && typeof node.detail === 'string' ? node.detail : 'No evaluation detail.';
        const resultKind =
          node && typeof node.resultKind === 'string' ? node.resultKind : null;

        if (matched === true) {
          matchedCount += 1;
          setConditionResultState(card, 'pass', 'Pass: ' + detail);
          return;
        }

        if (resultKind === 'missing_data') {
          setConditionResultState(card, 'review', 'Missing data: ' + detail);
          return;
        }

        if (matched === false) {
          setConditionResultState(card, 'fail', 'Fail: ' + detail);
          return;
        }

        setConditionResultState(card, 'idle', 'Not evaluated.');
      });

      return {
        total: cards.length,
        matched: matchedCount,
      };
    };

    const setSummaryText = (element, value) => {
      if (element instanceof HTMLElement) {
        element.textContent = value;
      }
    };

    const setSummaryTone = (element, tone) => {
      if (!(element instanceof HTMLElement)) {
        return;
      }

      if (typeof tone !== 'string' || tone.length === 0) {
        delete element.dataset.tone;
        return;
      }

      element.dataset.tone = tone;
    };

    const syncConditionCanvasMeta = () => {
      const cards = getConditionCards();

      cards.forEach((card, index) => {
        const indexElement = card.querySelector('[data-condition-index]');

        if (indexElement instanceof HTMLElement) {
          indexElement.textContent = 'Requirement ' + String(index + 1);
        }

        const moveUpButton = card.querySelector('button[data-condition-move="up"]');
        const moveDownButton = card.querySelector('button[data-condition-move="down"]');

        if (moveUpButton instanceof HTMLButtonElement) {
          moveUpButton.disabled = index === 0;
        }

        if (moveDownButton instanceof HTMLButtonElement) {
          moveDownButton.disabled = index === cards.length - 1;
        }
      });

      if (ruleBuilderConditionEmpty instanceof HTMLElement) {
        ruleBuilderConditionEmpty.hidden = cards.length > 0;
      }

      if (ruleBuilderCanvasCount instanceof HTMLElement) {
        ruleBuilderCanvasCount.textContent =
          String(cards.length) + (cards.length === 1 ? ' requirement' : ' requirements');
      }

      if (ruleBuilderCanvasLogic instanceof HTMLElement) {
        ruleBuilderCanvasLogic.textContent =
          getRuleBuilderRootLogic() === 'any' ? 'Alternative paths' : 'All requirements';
        ruleBuilderCanvasLogic.dataset.tone = getRuleBuilderRootLogic() === 'any' ? 'warning' : 'success';
      }
    };

    const syncRuleBuilderStepCompletion = () => {
      const completion = getRuleBuilderCompletionState();

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const targetStep = candidate.dataset.ruleStepTarget ?? '';
        const isDone = completion[targetStep] === true;
        candidate.classList.toggle('is-done', isDone);
      });

      const completedCount = Object.values(completion).filter((value) => value).length;
      const activeStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';
      const activeStepLabel = ruleBuilderStepLabels[activeStep] ?? 'Step';

      if (ruleBuilderStepProgress instanceof HTMLElement) {
        ruleBuilderStepProgress.textContent =
          'Step ' +
          String(activeRuleBuilderStepIndex + 1) +
          ' of ' +
          String(ruleBuilderStepOrder.length) +
          ' · ' +
          activeStepLabel +
          ' · ' +
          String(completedCount) +
          '/' +
          String(ruleBuilderStepOrder.length) +
          ' complete';
      }

      updateStepNavigationState();
    };

    const syncRuleBuilderSummary = (statusOverride) => {
      renderRuleFlowPreview();
      renderSourceReadiness();

      const ruleName = getTextFieldValue('name');
      const cardCount = getConditionCards().length;
      const rootLogicLabel =
        getRuleBuilderRootLogic() === 'any' ? 'Alternative paths' : 'All requirements';
      let definitionStatus = 'Drafting';
      let definitionTone = 'warning';
      let summaryMessage = 'Add at least one requirement to create a draft.';

      if (cardCount === 0) {
        definitionStatus = 'Needs requirements';
        definitionTone = 'warning';
      } else {
        const validationErrors = validateConditionCards(false);

        if (validationErrors.length > 0) {
          definitionStatus = 'Needs attention';
          definitionTone = 'error';
          summaryMessage = validationErrors[0];
        } else {
          try {
            const definition = readDefinitionFromBuilder(true);
            const rootConditions =
              definition &&
              typeof definition === 'object' &&
              definition.conditions &&
              typeof definition.conditions === 'object'
                ? definition.conditions
                : null;
            const childCount =
              rootConditions !== null && Array.isArray(rootConditions.all)
                ? rootConditions.all.length
                : rootConditions !== null && Array.isArray(rootConditions.any)
                  ? rootConditions.any.length
                  : cardCount;

            definitionStatus = childCount > 0 ? 'Ready for review' : 'Needs requirements';
            definitionTone = childCount > 0 ? 'success' : 'warning';
            summaryMessage =
              childCount > 0
                ? 'Requirements are synchronized with the generated rule JSON.'
                : 'Add one or more requirements to continue.';
          } catch (error) {
            definitionStatus = 'Needs attention';
            definitionTone = 'error';
            summaryMessage =
              error instanceof Error ? error.message : 'Definition is not ready for submission.';
          }
        }
      }

      let lastTestTone = 'info';

      if (ruleBuilderLastTestSummary.startsWith('Matched')) {
        lastTestTone = 'success';
      } else if (ruleBuilderLastTestSummary.startsWith('Review required')) {
        lastTestTone = 'warning';
      } else if (ruleBuilderLastTestSummary.startsWith('No match')) {
        lastTestTone = 'warning';
      } else if (
        ruleBuilderLastTestSummary.startsWith('Failed') ||
        ruleBuilderLastTestSummary.includes('invalid') ||
        ruleBuilderLastTestSummary.includes('Missing')
      ) {
        lastTestTone = 'error';
      }

      setSummaryText(
        ruleBuilderSummaryRuleName,
        ruleName.length > 0 ? ruleName : '(unnamed draft)',
      );
      setSummaryText(ruleBuilderSummaryConditionCount, String(cardCount));
      setSummaryText(ruleBuilderSummaryRootLogic, rootLogicLabel);
      setSummaryText(ruleBuilderSummaryValidity, definitionStatus);
      setSummaryText(ruleBuilderSummaryLastTest, ruleBuilderLastTestSummary);
      setSummaryText(ruleBuilderSummaryMessage, statusOverride ?? summaryMessage);
      setSummaryTone(ruleBuilderSummaryValidity, definitionTone);
      setSummaryTone(ruleBuilderSummaryLastTest, lastTestTone);
      setSummaryTone(
        ruleBuilderSummaryMessage,
        statusOverride === undefined
          ? definitionTone
          : ruleCreateStatus.dataset.tone === 'error'
            ? 'error'
            : ruleCreateStatus.dataset.tone === 'success'
              ? 'success'
              : ruleCreateStatus.dataset.tone === 'warning'
                ? 'warning'
                : 'info',
      );
      syncRuleBuilderStepCompletion();
    };

    const syncDefinitionJsonFromBuilder = () => {
      syncConditionCanvasMeta();
      renderRuleFlowPreview();
      renderSourceReadiness();

      try {
        const definition = readDefinitionFromBuilder(false);
        ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
      } catch {
        // Ignore transient editing errors while user updates fields.
      }

      ruleBuilderLastTestSummary = 'Not run';
      validateConditionCards(true);
      getConditionCards().forEach((card) => {
        updateConditionPlainSummary(card);
      });
      syncRuleBuilderSummary();
    };

    const createConditionCard = (seed) => {
      const card = cloneRuleBuilderConditionCard();

      if (!(card instanceof HTMLElement)) {
        return null;
      }

      const typeSelect = card.querySelector('.ct-admin__condition-type');

      if (typeSelect instanceof HTMLSelectElement) {
        typeSelect.value = typeof seed.type === 'string' ? seed.type : 'grade_threshold';
      }

      setCheckboxOnCard(card, 'negate', Boolean(seed.negate));
      renderConditionFields(card, seed);
      setConditionResultState(card, 'idle', 'Not evaluated yet.');

      card.addEventListener('change', (event) => {
        const target = event.target;

        if (target instanceof HTMLSelectElement && target.classList.contains('ct-admin__condition-type')) {
          renderConditionFields(card, {
            type: target.value,
            negate: readCheckboxFromCard(card, 'negate'),
          });
        }

        syncDefinitionJsonFromBuilder();
      });

      card.addEventListener('input', () => {
        syncDefinitionJsonFromBuilder();
      });

      card.addEventListener('click', (event) => {
        const target = event.target;

        if (target instanceof HTMLButtonElement && target.dataset.conditionMove === 'up') {
          const previous = card.previousElementSibling;

          if (previous instanceof HTMLElement) {
            ruleBuilderConditionList.insertBefore(card, previous);
          }

          syncDefinitionJsonFromBuilder();
          return;
        }

        if (target instanceof HTMLButtonElement && target.dataset.conditionMove === 'down') {
          const next = card.nextElementSibling;

          if (next instanceof HTMLElement) {
            ruleBuilderConditionList.insertBefore(next, card);
          }

          syncDefinitionJsonFromBuilder();
          return;
        }

        if (target instanceof HTMLButtonElement && target.classList.contains('ct-admin__condition-remove')) {
          card.remove();
          syncDefinitionJsonFromBuilder();
        }
      });

      card.addEventListener('dragstart', () => {
        card.classList.add('is-dragging');
      });

      card.addEventListener('dragend', () => {
        card.classList.remove('is-dragging');
        syncDefinitionJsonFromBuilder();
      });

      return card;
    };

    const getDragAfterElement = (container, y) => {
      const cards = Array.from(
        container.querySelectorAll('.ct-admin__condition-card:not(.is-dragging)'),
      );
      let closestOffset = Number.NEGATIVE_INFINITY;
      let closestElement = null;

      cards.forEach((card) => {
        if (!(card instanceof HTMLElement)) {
          return;
        }

        const box = card.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;

        if (offset < 0 && offset > closestOffset) {
          closestOffset = offset;
          closestElement = card;
        }
      });

      return closestElement;
    };

    ruleBuilderConditionList.addEventListener('dragover', (event) => {
      event.preventDefault();
      const dragging = ruleBuilderConditionList.querySelector('.ct-admin__condition-card.is-dragging');

      if (!(dragging instanceof HTMLElement)) {
        return;
      }

      const afterElement = getDragAfterElement(ruleBuilderConditionList, event.clientY);

      if (afterElement === null) {
        ruleBuilderConditionList.appendChild(dragging);
        return;
      }

      ruleBuilderConditionList.insertBefore(dragging, afterElement);
    });

    const clearConditionCanvas = () => {
      ruleBuilderConditionList.innerHTML = '';
    };

    const addConditionToCanvas = (seed) => {
      const card = createConditionCard(seed);

      if (!(card instanceof HTMLElement)) {
        setStatus(ruleCreateStatus, 'Unable to add requirement row.', true);
        return;
      }

      ruleBuilderConditionList.appendChild(card);
      syncDefinitionJsonFromBuilder();
    };

    const refreshConditionCardValueListOptions = () => {
      getConditionCards().forEach((card) => {
        try {
          const currentCondition = readConditionFromCard(card, false);
          const normalizedCondition = normalizeLeafConditionForBuilder(currentCondition);

          if (normalizedCondition === null) {
            return;
          }

          const typeSelect = card.querySelector('.ct-admin__condition-type');

          if (typeSelect instanceof HTMLSelectElement) {
            typeSelect.value = normalizedCondition.type;
          }

          setCheckboxOnCard(card, 'negate', Boolean(normalizedCondition.negate));
          renderConditionFields(card, normalizedCondition);
        } catch {
          // Ignore partially edited cards while refreshing reusable-list options.
        }
      });
    };

    const normalizeLeafConditionForBuilder = (condition) => {
      if (condition === null || typeof condition !== 'object' || Array.isArray(condition)) {
        return null;
      }

      if ('type' in condition && typeof condition.type === 'string') {
        return {
          ...condition,
          negate: false,
        };
      }

      if ('not' in condition) {
        const nested = normalizeLeafConditionForBuilder(condition.not);

        if (nested === null) {
          return null;
        }

        return {
          ...nested,
          negate: true,
        };
      }

      return null;
    };

    const applyDefinitionToBuilder = (definition, sourceLabel) => {
      if (definition === null || typeof definition !== 'object' || !('conditions' in definition)) {
        throw new Error('Rule definition must include a conditions object.');
      }

      const reviewOnMissingFacts =
        definition.options &&
        typeof definition.options === 'object' &&
        definition.options.reviewOnMissingFacts === true;
      const reviewOnMissingFactsField = getRuleCreateField('reviewOnMissingFacts');

      if (reviewOnMissingFactsField instanceof HTMLInputElement) {
        reviewOnMissingFactsField.checked = reviewOnMissingFacts;
      }

      const rootConditions = definition.conditions;
      let rootLogic = 'all';
      let rawChildren = [];

      if (rootConditions && typeof rootConditions === 'object' && Array.isArray(rootConditions.all)) {
        rootLogic = 'all';
        rawChildren = rootConditions.all;
      } else if (rootConditions && typeof rootConditions === 'object' && Array.isArray(rootConditions.any)) {
        rootLogic = 'any';
        rawChildren = rootConditions.any;
      } else {
        rawChildren = [rootConditions];
      }

      const normalizedChildren = rawChildren
        .map((condition) => normalizeLeafConditionForBuilder(condition))
        .filter((condition) => condition !== null);

      if (normalizedChildren.length !== rawChildren.length) {
        setStatus(
          ruleCreateStatus,
          sourceLabel +
            ' includes nested requirement groups not editable as rows. JSON mode remains active.',
          true,
        );
        syncRuleBuilderSummary(
          sourceLabel +
            ' includes nested requirement groups not editable as rows. Adjust JSON manually.',
        );
        return;
      }

      clearConditionCanvas();
      setRuleBuilderRootLogic(rootLogic);
      normalizedChildren.forEach((seed) => {
        addConditionToCanvas(seed);
      });

      if (normalizedChildren.length === 0) {
        addConditionToCanvas({
          type: 'course_completion',
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
          requireCompleted: true,
          negate: false,
        });
      }

      syncDefinitionJsonFromBuilder();
      setStatus(ruleCreateStatus, sourceLabel + ' loaded into visual builder.', false, 'success');
      syncRuleBuilderSummary(sourceLabel + ' loaded into visual builder.');
    };

    const parseDefinitionJson = () => {
      const definitionJsonText = ruleBuilderDefinitionJson.value.trim();
      const fallbackDefinition = readDefinitionFromBuilder(true);

      if (definitionJsonText.length === 0) {
        return fallbackDefinition;
      }

      let parsed;

      try {
        parsed = JSON.parse(definitionJsonText);
      } catch {
        throw new Error('Rule JSON is not valid JSON.');
      }

      if (parsed === null || typeof parsed !== 'object' || !('conditions' in parsed)) {
        throw new Error('Rule JSON must include a top-level conditions object.');
      }

      return parsed;
    };

    const applyTemplatePreset = () => {
      const presetKey =
        ruleBuilderTemplatePreset instanceof HTMLSelectElement
          ? ruleBuilderTemplatePreset.value.trim()
          : 'course_and_grade';

      if (presetKey === 'blank') {
        clearConditionCanvas();
        setRuleBuilderRootLogic('all');
        ruleBuilderDefinitionJson.value = '';
        ruleBuilderLastTestSummary = 'Not run';
        syncConditionCanvasMeta();
        renderRuleFlowPreview();
        renderSourceReadiness();
        validateConditionCards(true);
        setStatus(ruleCreateStatus, 'Blank requirements started.', false, 'success');
        syncSuggestedRuleName();
        syncRuleBuilderSummary('Blank requirements started.');
        return;
      }

      const selectedTemplate =
        buildDefaultTemplateDefinitions(getDefaultCourseId())[presetKey] ??
        buildDefaultTemplateDefinitions(getDefaultCourseId()).course_and_grade;
      ruleBuilderDefinitionJson.value = JSON.stringify(selectedTemplate, null, 2);
      applyDefinitionToBuilder(selectedTemplate, 'Template');
      syncSuggestedRuleName();
    };

    const applyTestFactPreset = () => {
      const presetKey =
        ruleBuilderTemplatePreset instanceof HTMLSelectElement
          ? ruleBuilderTemplatePreset.value.trim()
          : ruleBuilderTestPresetSelect instanceof HTMLSelectElement
            ? ruleBuilderTestPresetSelect.value.trim()
            : 'canvas_course_grade';
      const learnerId = getTextFieldValue('testLearnerId') || 'canvas:12345';
      const recipientIdentity = getTextFieldValue('testRecipientIdentity') || 'learner@example.edu';
      const courseId = getDefaultCourseId() || getCoursePlaceholder();
      const programCourseIds = deriveRelatedCourseIds(courseId, 3);
      const nextCourseId = programCourseIds[1] ?? courseId + '-2';
      const surveyId = courseId + '_EXIT_SURVEY';

      setRuleCreateFieldValue('testLearnerId', learnerId);
      setRuleCreateFieldValue('testRecipientIdentity', recipientIdentity);

      if (presetKey === 'program_completion') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              completions: programCourseIds.map((entry) => {
                return {
                  courseId: entry,
                  learnerId,
                  completed: true,
                  completionPercent: 100,
                };
              }),
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'assignment_submission') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '88');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              submissions: [
                {
                  courseId,
                  assignmentId: 'assignment_1',
                  learnerId,
                  score: 88,
                  workflowState: 'submitted',
                  submittedAt: new Date().toISOString(),
                },
              ],
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'prerequisite_chain' || presetKey === 'prerequisite_badge') {
        setRuleCreateFieldValue('testCourseId', nextCourseId);
        setRuleCreateFieldValue('testFinalScore', '95');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              earnedBadgeTemplateIds: ['badge_template_foundations'],
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'survey_completion') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              surveyCompletions: [
                {
                  surveyId,
                  learnerId,
                  source: 'qualtrics',
                  completed: true,
                  completedAt: new Date().toISOString(),
                },
              ],
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'custom_field') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              customFields: [
                {
                  learnerId,
                  fieldName: 'programStanding',
                  value: 'eligible',
                },
              ],
            },
            null,
            2,
          ),
        );
      } else {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue('testFactsJson', '');
      }

      const testCompletedField = getRuleCreateField('testCompleted');

      if (testCompletedField instanceof HTMLInputElement) {
        testCompletedField.checked = true;
      }

      ruleBuilderLastTestSummary = 'Not run';
      renderSourceReadiness();
      validateConditionCards(true);
      setStatus(ruleCreateStatus, 'Applied test facts preset.', false);
      syncRuleBuilderSummary('Applied test facts preset.');
    };

    const buildApprovalChain = (approvalRolesText) => {
      const approvalRoles =
        approvalRolesText.length === 0
          ? []
          : approvalRolesText
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0);
      const invalidRole = approvalRoles.find((role) => !validRoles.has(role));

      if (invalidRole !== undefined) {
        throw new Error('Invalid approval role: ' + invalidRole + '. Use owner/admin/issuer/viewer.');
      }

      return approvalRoles.map((requiredRole, index) => {
        return {
          requiredRole,
          label: 'Step ' + String(index + 1) + ' · ' + requiredRole,
        };
      });
    };

    if (ruleBuilderStepButtons.length > 0) {
      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        candidate.addEventListener('click', () => {
          const targetStep = candidate.dataset.ruleStepTarget ?? '';
          const targetIndex = ruleBuilderStepOrder.indexOf(targetStep);

          if (targetIndex >= 0) {
            tryNavigateToStep(targetIndex);
          }
        });
      });
    }

    if (ruleBuilderStepPrevButton instanceof HTMLButtonElement) {
      ruleBuilderStepPrevButton.addEventListener('click', () => {
        tryNavigateToStep(activeRuleBuilderStepIndex - 1);
      });
    }

    if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
      ruleBuilderStepNextButton.addEventListener('click', () => {
        const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';

        if (!isStepComplete(currentStep)) {
          showStepGateMessage(currentStep);
          return;
        }

        tryNavigateToStep(activeRuleBuilderStepIndex + 1);
      });
    }

    if (ruleBuilderReturnToPatternButton instanceof HTMLButtonElement) {
      ruleBuilderReturnToPatternButton.addEventListener('click', () => {
        tryNavigateToStep(0);
      });
    }

    ruleCreateForm.addEventListener('input', () => {
      syncRuleBuilderSummary();
    });

    ruleCreateForm.addEventListener('change', () => {
      syncRuleBuilderSummary();
    });

    const reviewOnMissingFactsField = getRuleCreateField('reviewOnMissingFacts');

    if (reviewOnMissingFactsField instanceof HTMLInputElement) {
      reviewOnMissingFactsField.addEventListener('change', () => {
        syncDefinitionJsonFromBuilder();
      });
    }

    if (ruleBuilderAddConditionButton instanceof HTMLButtonElement) {
      ruleBuilderAddConditionButton.addEventListener('click', () => {
        addConditionToCanvas({
          type: 'course_completion',
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
          requireCompleted: true,
          negate: false,
        });
      });
    }

    if (ruleBuilderAddAlternativePathButton instanceof HTMLButtonElement) {
      ruleBuilderAddAlternativePathButton.addEventListener('click', () => {
        setRuleBuilderRootLogic('any');
        addConditionToCanvas({
          type: 'grade_threshold',
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
          scoreField: 'final_score',
          minScore: 80,
          negate: false,
        });
        syncRuleBuilderSummary('Alternative earning path added.');
      });
    }

    if (ruleBuilderApplyTemplateButton instanceof HTMLButtonElement) {
      ruleBuilderApplyTemplateButton.addEventListener('click', () => {
        applyTemplatePreset();
      });
    }

    if (ruleBuilderApplyTestPresetButton instanceof HTMLButtonElement) {
      ruleBuilderApplyTestPresetButton.addEventListener('click', () => {
        applyTestFactPreset();
      });
    }

    if (ruleBuilderApplyJsonButton instanceof HTMLButtonElement) {
      ruleBuilderApplyJsonButton.addEventListener('click', () => {
        try {
          const definition = parseDefinitionJson();
          applyDefinitionToBuilder(definition, 'JSON');
        } catch (error) {
          setStatus(
            ruleCreateStatus,
            error instanceof Error ? error.message : 'Unable to apply JSON to builder.',
            true,
          );
        }
      });
    }

    document.querySelectorAll('[data-rule-builder-root-logic-option]').forEach((candidate) => {
      if (candidate instanceof HTMLInputElement) {
        candidate.addEventListener('change', () => {
          if (candidate.checked) {
            setRuleBuilderRootLogic(candidate.value);
            syncDefinitionJsonFromBuilder();
          }
        });
      }
    });

    if (ruleBuilderSaveDraftButton instanceof HTMLButtonElement) {
      ruleBuilderSaveDraftButton.addEventListener('click', () => {
        try {
          const draft = {
            savedAt: new Date().toISOString(),
            name: getTextFieldValue('name'),
            description: getTextFieldValue('description'),
            badgeTemplateId: getTextFieldValue('badgeTemplateId'),
            lmsProviderKind: getTextFieldValue('lmsProviderKind'),
            approvalRoles: getTextFieldValue('approvalRoles'),
            changeSummary: getTextFieldValue('changeSummary'),
            issuanceTiming: getTextFieldValue('issuanceTiming'),
            testLearnerId: getTextFieldValue('testLearnerId'),
            testRecipientIdentity: getTextFieldValue('testRecipientIdentity'),
            testCourseId: getTextFieldValue('testCourseId'),
            testFinalScore: getTextFieldValue('testFinalScore'),
            testFactsJson: getTextFieldValue('testFactsJson'),
            testCompleted: getCheckboxFieldValue('testCompleted'),
            definition: parseDefinitionJson(),
          };
          localStorage.setItem(ruleBuilderDraftStorageKey, JSON.stringify(draft));
          setStatus(
            ruleCreateStatus,
            'Rule builder draft saved.',
            false,
            'success',
          );
          syncRuleBuilderSummary('Rule builder draft saved.');
        } catch (error) {
          setStatus(
            ruleCreateStatus,
            error instanceof Error ? error.message : 'Unable to save draft.',
            true,
          );
          syncRuleBuilderSummary(
            error instanceof Error ? error.message : 'Unable to save draft.',
          );
        }
      });
    }

    if (ruleBuilderLoadDraftButton instanceof HTMLButtonElement) {
      ruleBuilderLoadDraftButton.addEventListener('click', () => {
        const rawDraft = localStorage.getItem(ruleBuilderDraftStorageKey);

        if (rawDraft === null) {
          setStatus(ruleCreateStatus, 'No saved draft found.', true);
          syncRuleBuilderSummary('No saved draft found.');
          return;
        }

        try {
          const draft = JSON.parse(rawDraft);
          setRuleCreateFieldValue('name', typeof draft.name === 'string' ? draft.name : '');
          setRuleCreateFieldValue('description', typeof draft.description === 'string' ? draft.description : '');
          setRuleCreateFieldValue('badgeTemplateId', typeof draft.badgeTemplateId === 'string' ? draft.badgeTemplateId : '');
          setRuleCreateFieldValue('lmsProviderKind', typeof draft.lmsProviderKind === 'string' ? draft.lmsProviderKind : 'canvas');
          setRuleCreateFieldValue('approvalRoles', typeof draft.approvalRoles === 'string' ? draft.approvalRoles : 'admin,owner');
          setRuleCreateFieldValue('changeSummary', typeof draft.changeSummary === 'string' ? draft.changeSummary : '');
          setRuleCreateFieldValue('issuanceTiming', typeof draft.issuanceTiming === 'string' ? draft.issuanceTiming : 'immediate');
          setRuleCreateFieldValue('testLearnerId', typeof draft.testLearnerId === 'string' ? draft.testLearnerId : 'canvas:12345');
          setRuleCreateFieldValue('testRecipientIdentity', typeof draft.testRecipientIdentity === 'string' ? draft.testRecipientIdentity : 'learner@example.edu');
          setRuleCreateFieldValue(
            'testCourseId',
            typeof draft.testCourseId === 'string'
              ? draft.testCourseId
              : getDefaultCourseId() || getCoursePlaceholder(),
          );
          setRuleCreateFieldValue('testFinalScore', typeof draft.testFinalScore === 'string' ? draft.testFinalScore : '92');
          setRuleCreateFieldValue('testFactsJson', typeof draft.testFactsJson === 'string' ? draft.testFactsJson : '');
          const testCompletedField = getRuleCreateField('testCompleted');

          if (testCompletedField instanceof HTMLInputElement) {
            testCompletedField.checked = draft.testCompleted === undefined ? true : Boolean(draft.testCompleted);
          }

          const definition = draft && typeof draft.definition === 'object' ? draft.definition : null;

          if (definition !== null) {
            ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
            applyDefinitionToBuilder(definition, 'Saved draft');
          } else {
            syncDefinitionJsonFromBuilder();
          }
        } catch {
          setStatus(ruleCreateStatus, 'Saved draft data is invalid JSON.', true);
          syncRuleBuilderSummary('Saved draft data is invalid JSON.');
        }
      });
    }

    if (
      ruleBuilderImportJsonButton instanceof HTMLButtonElement &&
      ruleBuilderImportFileInput instanceof HTMLInputElement
    ) {
      ruleBuilderImportJsonButton.addEventListener('click', () => {
        ruleBuilderImportFileInput.click();
      });

      ruleBuilderImportFileInput.addEventListener('change', async () => {
        const file = ruleBuilderImportFileInput.files?.item(0);

        if (!(file instanceof File)) {
          return;
        }

        try {
          const text = await file.text();
          const parsed = JSON.parse(text);
          const definition =
            parsed && typeof parsed === 'object' && 'definition' in parsed
              ? parsed.definition
              : parsed && typeof parsed === 'object' && 'conditions' in parsed
                ? parsed
                : null;

          if (
            parsed !== null &&
            typeof parsed === 'object' &&
            !Array.isArray(parsed) &&
            'name' in parsed &&
            typeof parsed.name === 'string'
          ) {
            setRuleCreateFieldValue('name', parsed.name);
          }

          if (
            parsed !== null &&
            typeof parsed === 'object' &&
            !Array.isArray(parsed) &&
            'description' in parsed &&
            typeof parsed.description === 'string'
          ) {
            setRuleCreateFieldValue('description', parsed.description);
          }

          if (
            parsed !== null &&
            typeof parsed === 'object' &&
            !Array.isArray(parsed) &&
            'badgeTemplateId' in parsed &&
            typeof parsed.badgeTemplateId === 'string'
          ) {
            setRuleCreateFieldValue('badgeTemplateId', parsed.badgeTemplateId);
          }

          if (
            parsed !== null &&
            typeof parsed === 'object' &&
            !Array.isArray(parsed) &&
            'lmsProviderKind' in parsed &&
            typeof parsed.lmsProviderKind === 'string'
          ) {
            setRuleCreateFieldValue('lmsProviderKind', parsed.lmsProviderKind);
          }

          if (definition === null) {
            throw new Error('Imported JSON must contain definition.conditions or conditions.');
          }

          ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
          applyDefinitionToBuilder(definition, 'Imported JSON');
          ruleBuilderImportFileInput.value = '';
        } catch (error) {
          setStatus(
            ruleCreateStatus,
            error instanceof Error ? error.message : 'Unable to import JSON.',
            true,
          );
          ruleBuilderImportFileInput.value = '';
        }
      });
    }

    if (ruleBuilderExportJsonButton instanceof HTMLButtonElement) {
      ruleBuilderExportJsonButton.addEventListener('click', () => {
        try {
          const definition = parseDefinitionJson();
          const payload = {
            name: getTextFieldValue('name'),
            description: getTextFieldValue('description'),
            badgeTemplateId: getTextFieldValue('badgeTemplateId'),
            lmsProviderKind: getTextFieldValue('lmsProviderKind'),
            definition,
          };
          const blob = new Blob([JSON.stringify(payload, null, 2)], {
            type: 'application/json',
          });
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement('a');
          const exportName =
            payload.name.length === 0
              ? 'rule-definition.json'
              : payload.name
                  .toLowerCase()
                  .replace(/[^a-z0-9]+/g, '-')
                  .replace(/^-+|-+$/g, '') + '.json';
          anchor.href = url;
          anchor.download = exportName;
          anchor.click();
          URL.revokeObjectURL(url);
          setStatus(ruleCreateStatus, 'Rule JSON exported.', false, 'success');
          syncRuleBuilderSummary('Rule JSON exported.');
        } catch (error) {
          setStatus(
            ruleCreateStatus,
            error instanceof Error ? error.message : 'Unable to export JSON.',
            true,
          );
          syncRuleBuilderSummary(
            error instanceof Error ? error.message : 'Unable to export JSON.',
          );
        }
      });
    }

    if (
      ruleBuilderCloneLoadButton instanceof HTMLButtonElement &&
      ruleBuilderCloneRuleSelect instanceof HTMLSelectElement
    ) {
      ruleBuilderCloneLoadButton.addEventListener('click', async () => {
        const ruleId = ruleBuilderCloneRuleSelect.value.trim();

        if (ruleId.length === 0) {
          setStatus(ruleCreateStatus, 'Select a rule to clone.', true);
          syncRuleBuilderSummary('Select a rule to clone.');
          return;
        }

        setStatus(ruleCreateStatus, 'Loading rule for clone...', false);
        syncRuleBuilderSummary('Loading rule for clone...');

        try {
          const response = await fetch(badgeRuleApiPath + '/' + encodeURIComponent(ruleId));
          const payload = await parseJsonBody(response);

          if (!response.ok) {
            setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
            syncRuleBuilderSummary(errorDetailFromPayload(payload));
            return;
          }

          const rule = payload && payload.rule ? payload.rule : null;
          const versions = payload && Array.isArray(payload.versions) ? payload.versions : [];
          const latestVersion = versions
            .slice()
            .sort((left, right) => {
              const leftVersion = typeof left.versionNumber === 'number' ? left.versionNumber : 0;
              const rightVersion = typeof right.versionNumber === 'number' ? right.versionNumber : 0;
              return rightVersion - leftVersion;
            })[0];

          if (rule && typeof rule.name === 'string') {
            const clonedName = rule.name + ' copy';
            ruleNameManuallyEdited = true;
            setRuleCreateFieldValue('name', clonedName);

            if (ruleBuilderNameVisible instanceof HTMLInputElement) {
              ruleBuilderNameVisible.value = clonedName;
            }
          }

          if (rule && typeof rule.description === 'string' && rule.description.length > 0) {
            setRuleCreateFieldValue('description', rule.description);
          }

          if (rule && typeof rule.badgeTemplateId === 'string') {
            setRuleCreateFieldValue('badgeTemplateId', rule.badgeTemplateId);
          }

          if (rule && typeof rule.lmsProviderKind === 'string') {
            setRuleCreateFieldValue('lmsProviderKind', rule.lmsProviderKind);
          }

          if (latestVersion && typeof latestVersion.ruleJson === 'string') {
            const definition = JSON.parse(latestVersion.ruleJson);
            ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
            applyDefinitionToBuilder(definition, 'Cloned rule');
          } else {
            setStatus(ruleCreateStatus, 'Selected rule has no version JSON to clone.', true);
            syncRuleBuilderSummary('Selected rule has no version JSON to clone.');
          }
        } catch {
          setStatus(ruleCreateStatus, 'Unable to clone selected rule from this browser session.', true);
          syncRuleBuilderSummary('Unable to clone selected rule from this browser session.');
        }
      });
    }

    runRuleBuilderTest = async (options) => {
      const autoRun = options && options.auto === true;
      const runningMessage = autoRun
        ? 'Running automatic test with sample learner...'
        : 'Evaluating rule in test mode...';

      setStatus(ruleCreateStatus, runningMessage, false);
      setCodeOutput(ruleBuilderTestOutput, '');

      if (ruleBuilderTestResult instanceof HTMLElement) {
        setStatus(ruleBuilderTestResult, runningMessage, false);
      }

      resetConditionEvaluationResults();
      ruleBuilderLastTestSummary = 'Running...';
      syncRuleBuilderSummary(runningMessage);

      let definition;

      try {
        definition = parseDefinitionJson();
      } catch (error) {
        const message =
          error instanceof Error ? error.message : 'Rule definition is invalid.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Definition invalid';
        syncRuleBuilderSummary(message);
        return;
      }

      const learnerId = getTextFieldValue('testLearnerId');
      const recipientIdentity = getTextFieldValue('testRecipientIdentity').toLowerCase();
      const lmsProviderKind = getTextFieldValue('lmsProviderKind');
      const sampleCourseId = getTextFieldValue('testCourseId');
      const sampleFinalScoreText = getTextFieldValue('testFinalScore');
      const testFactsJson = getTextFieldValue('testFactsJson');
      const testCompleted = getCheckboxFieldValue('testCompleted');

      if (learnerId.length === 0 || recipientIdentity.length === 0) {
        const message = 'Test mode requires learner ID and recipient email.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Missing test identifiers';
        syncRuleBuilderSummary(message);
        return;
      }

      let facts = undefined;

      if (testFactsJson.length > 0) {
        try {
          facts = JSON.parse(testFactsJson);
        } catch {
          const message = 'Advanced facts JSON is invalid.';
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Facts JSON invalid';
          syncRuleBuilderSummary(message);
          return;
        }
      } else if (sampleCourseId.length > 0) {
        const sampleFinalScore = Number(sampleFinalScoreText);

        if (!Number.isFinite(sampleFinalScore) || sampleFinalScore < 0 || sampleFinalScore > 100) {
          const message = 'Sample final score must be a number between 0 and 100.';
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Sample score invalid';
          syncRuleBuilderSummary(message);
          return;
        }

        facts = {
          grades: [
            {
              courseId: sampleCourseId,
              learnerId,
              finalScore: sampleFinalScore,
            },
          ],
          completions: [
            {
              courseId: sampleCourseId,
              learnerId,
              completed: testCompleted,
              completionPercent: testCompleted ? 100 : 0,
            },
          ],
        };
      }

      try {
        const response = await fetch(badgeRulePreviewApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            definition,
            lmsProviderKind: lmsProviderKind.length === 0 ? 'canvas' : lmsProviderKind,
            learnerId,
            recipientIdentity,
            recipientIdentityType: 'email',
            ...(facts === undefined ? {} : { facts }),
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          const message = errorDetailFromPayload(payload);
          setStatus(ruleCreateStatus, message, true);
          if (ruleBuilderTestResult instanceof HTMLElement) {
            setStatus(ruleBuilderTestResult, message, true);
          }
          ruleBuilderLastTestSummary = 'Failed';
          syncRuleBuilderSummary(message);
          return;
        }

        const matched =
          payload && payload.evaluation && payload.evaluation.matched === true;
        let outcome = 'no_match';

        if (payload && typeof payload.outcome === 'string') {
          outcome = payload.outcome;
        } else if (matched) {
          outcome = 'matched';
        }
        const evaluationSummary =
          payload && payload.evaluationSummary && typeof payload.evaluationSummary === 'object'
            ? payload.evaluationSummary
            : null;
        const missingDataCount =
          evaluationSummary && typeof evaluationSummary.missingDataCount === 'number'
            ? evaluationSummary.missingDataCount
            : 0;
        const conditionSummary = applyConditionEvaluationResults(
          payload && payload.evaluation ? payload.evaluation : null,
        );
        const conditionSummaryText =
          conditionSummary.total === 0
            ? ''
            : ' Requirements passed: ' +
              String(conditionSummary.matched) +
              '/' +
              String(conditionSummary.total) +
              '.';
        let outcomeLabel = 'no_match';

        if (outcome === 'review_required') {
          outcomeLabel = 'review_required';
        } else if (outcome === 'matched') {
          outcomeLabel = 'matched';
        }

        let resultMessage = '';

        if (outcome === 'review_required') {
          resultMessage =
            'Review required: ' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            ' requirements matched, with missing data for ' +
            String(missingDataCount) +
            ' check(s).';
        } else if (matched) {
          resultMessage =
            'Sample learner qualifies for this badge (' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            ' requirements matched).';
        } else {
          resultMessage =
            'Sample learner does not qualify yet (' +
            String(conditionSummary.matched) +
            ' of ' +
            String(conditionSummary.total) +
            ' requirements matched). Adjust requirements or test facts and run again.';
        }

        setStatus(
          ruleCreateStatus,
          'Test evaluation complete. outcome=' +
            outcomeLabel +
            '.' +
            (missingDataCount > 0 ? ' Missing data=' + String(missingDataCount) + '.' : '') +
            conditionSummaryText,
          false,
          outcome === 'matched' ? 'success' : 'warning',
        );

        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(
            ruleBuilderTestResult,
            resultMessage,
            false,
            outcome === 'matched' ? 'success' : 'warning',
          );
        }

        if (outcome === 'review_required') {
          ruleBuilderLastTestSummary =
            'Review required (' +
            String(missingDataCount) +
            ' missing, ' +
            String(conditionSummary.matched) +
            '/' +
            String(conditionSummary.total) +
            ' requirements matched)';
        } else {
          ruleBuilderLastTestSummary =
            (matched ? 'Matched' : 'No match') +
            ' (' +
            String(conditionSummary.matched) +
            '/' +
            String(conditionSummary.total) +
            ' requirements)';
        }

        syncRuleBuilderSummary(
          'Test evaluation complete. outcome=' +
            outcomeLabel +
            '.' +
            (missingDataCount > 0 ? ' Missing data=' + String(missingDataCount) + '.' : '') +
            conditionSummaryText,
        );
        setCodeOutput(ruleBuilderTestOutput, JSON.stringify(payload, null, 2));
      } catch {
        const message = 'Unable to run rule test from this browser session.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Failed';
        syncRuleBuilderSummary(message);
      }
    };

    if (ruleBuilderTestButton instanceof HTMLButtonElement) {
      ruleBuilderTestButton.addEventListener('click', () => {
        void runRuleBuilderTest({ auto: false });
      });
    }

    if (
      ruleBuilderSimulateButton instanceof HTMLButtonElement &&
      ruleBuilderSimulateLimit instanceof HTMLInputElement &&
      ruleBuilderSimulateStatus instanceof HTMLElement
    ) {
      ruleBuilderSimulateButton.addEventListener('click', async () => {
        setStatus(ruleBuilderSimulateStatus, 'Running historical simulation...', false);
        setCodeOutput(ruleBuilderSimulateOutput, '');

        let definition;

        try {
          definition = parseDefinitionJson();
        } catch (error) {
          setStatus(
            ruleBuilderSimulateStatus,
            error instanceof Error ? error.message : 'Rule definition is invalid.',
            true,
          );
          return;
        }

        const badgeTemplateId = getTextFieldValue('badgeTemplateId');
        const parsedSampleLimit = Number(ruleBuilderSimulateLimit.value.trim());
        const sampleLimit =
          Number.isFinite(parsedSampleLimit) && parsedSampleLimit >= 1 && parsedSampleLimit <= 100
            ? Math.trunc(parsedSampleLimit)
            : 25;

        if (badgeTemplateId.length === 0) {
          setStatus(ruleBuilderSimulateStatus, 'Badge template is required for simulation.', true);
          return;
        }

        try {
          const response = await fetch(badgeRulePreviewSimulationApiPath, {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              definition,
              badgeTemplateId,
              sampleLimit,
            }),
          });
          const payload = await parseJsonBody(response);

          if (!response.ok) {
            setStatus(ruleBuilderSimulateStatus, errorDetailFromPayload(payload), true);
            return;
          }

          const sampleCount =
            payload && typeof payload.sampleCount === 'number' ? payload.sampleCount : 0;
          const summary =
            payload && payload.summary && typeof payload.summary === 'object'
              ? payload.summary
              : null;
          const changedCount =
            summary && typeof summary.changedCount === 'number' ? summary.changedCount : 0;
          const reviewRequiredCount =
            summary && typeof summary.reviewRequiredCount === 'number'
              ? summary.reviewRequiredCount
              : 0;
          const matchedCount =
            summary && typeof summary.matchedCount === 'number' ? summary.matchedCount : 0;

          setStatus(
            ruleBuilderSimulateStatus,
            sampleCount === 0
              ? 'No historical evaluations are available for this badge template yet.'
              : 'Simulation complete. Samples=' +
                  String(sampleCount) +
                  ', matched=' +
                  String(matchedCount) +
                  ', review_required=' +
                  String(reviewRequiredCount) +
                  ', changed=' +
                  String(changedCount) +
                  '.',
            false,
            sampleCount === 0 ? 'warning' : 'success',
          );
          setCodeOutput(ruleBuilderSimulateOutput, JSON.stringify(payload, null, 2));
        } catch {
          setStatus(
            ruleBuilderSimulateStatus,
            'Unable to run historical simulation from this browser session.',
            true,
          );
        }
      });
    }

    ruleCreateForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(ruleCreateStatus, 'Creating rule draft...', false);
      setCodeOutput(ruleBuilderTestOutput, '');
      syncRuleBuilderSummary('Creating rule draft...');

      const name = getTextFieldValue('name');
      const description = getTextFieldValue('description');
      const badgeTemplateId = getTextFieldValue('badgeTemplateId');
      const lmsProviderKind = getTextFieldValue('lmsProviderKind');
      const approvalRolesText = getTextFieldValue('approvalRoles');
      const issuanceTiming = getTextFieldValue('issuanceTiming');
      const changeSummaryInput = getTextFieldValue('changeSummary');

      if (name.length === 0 || badgeTemplateId.length === 0 || lmsProviderKind.length === 0) {
        setStatus(
          ruleCreateStatus,
          'Rule name, badge template, and LMS provider are required.',
          true,
        );
        syncRuleBuilderSummary('Rule name, badge template, and LMS provider are required.');
        return;
      }

      let definition;
      let approvalChain;

      try {
        definition = parseDefinitionJson();
        approvalChain = buildApprovalChain(approvalRolesText);
      } catch (error) {
        setStatus(
          ruleCreateStatus,
          error instanceof Error ? error.message : 'Rule payload is invalid.',
          true,
        );
        syncRuleBuilderSummary(
          error instanceof Error ? error.message : 'Rule payload is invalid.',
        );
        return;
      }

      const definitionWithOptions = {
        ...definition,
        options: {
          ...(definition && typeof definition === 'object' && definition.options && typeof definition.options === 'object'
            ? definition.options
            : {}),
          issuanceTiming:
            issuanceTiming === 'manual' || issuanceTiming === 'end_of_term'
              ? issuanceTiming
              : 'immediate',
        },
      };

      let changeSummary = changeSummaryInput;
      const issuanceLabel = definitionWithOptions.options.issuanceTiming.replaceAll('_', ' ');

      if (changeSummary.length === 0) {
        changeSummary = 'Rule created via visual builder; issuance timing: ' + issuanceLabel + '.';
      } else if (!changeSummary.toLowerCase().includes('issuance timing')) {
        changeSummary =
          changeSummary + ' Issuance timing: ' + issuanceLabel + '.';
      }

      try {
        const response = await fetch(badgeRuleApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            name,
            ...(description.length > 0 ? { description } : {}),
            badgeTemplateId,
            lmsProviderKind,
            definition: definitionWithOptions,
            ...(approvalChain.length > 0 ? { approvalChain } : {}),
            ...(changeSummary.length > 0 ? { changeSummary } : {}),
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
          syncRuleBuilderSummary(errorDetailFromPayload(payload));
          return;
        }

        const ruleId = payload && payload.rule && typeof payload.rule.id === 'string' ? payload.rule.id : '';
        const versionId =
          payload && payload.version && typeof payload.version.id === 'string'
            ? payload.version.id
            : '';
        setStatus(
          ruleCreateStatus,
          'Rule draft created: ' + ruleId + (versionId.length > 0 ? ' (' + versionId + ')' : ''),
          false,
          'success',
        );
        syncRuleBuilderSummary(
          'Rule draft created: ' + ruleId + (versionId.length > 0 ? ' (' + versionId + ')' : ''),
        );
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(ruleCreateStatus, 'Unable to create rule draft from this browser session.', true);
        syncRuleBuilderSummary('Unable to create rule draft from this browser session.');
      }
    });

    if (ruleBuilderNameVisible instanceof HTMLInputElement) {
      ruleBuilderNameVisible.addEventListener('input', () => {
        ruleNameManuallyEdited = true;
        setRuleCreateFieldValue('name', ruleBuilderNameVisible.value.trim());
        syncRuleBuilderSummary();
      });
    }

    const badgeTemplateField = getRuleCreateField('badgeTemplateId');

    if (badgeTemplateField instanceof HTMLSelectElement) {
      badgeTemplateField.addEventListener('change', () => {
        syncSuggestedRuleName();
        syncRuleBuilderSummary();

        const courseId = getDefaultCourseId();

        if (courseId.length > 0) {
          setRuleCreateFieldValue('testCourseId', courseId);
        }

        if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
          applyTemplatePreset();
        }
      });
    }

    if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
      ruleBuilderTemplatePreset.addEventListener('change', () => {
        applyTemplatePreset();
        syncSuggestedRuleName();
        syncRuleBuilderSummary();
      });
    }

    setBuilderStepState(0);
    syncSuggestedRuleName();
    applyTemplatePreset();
    void loadRuleValueLists(null, {
      quietSuccess: true,
    }).then(() => {
      refreshConditionCardValueListOptions();
    });
    syncRuleBuilderSummary();
  }
})();
`;
