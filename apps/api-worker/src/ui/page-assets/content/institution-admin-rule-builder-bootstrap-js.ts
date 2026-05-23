export const INSTITUTION_ADMIN_RULE_BUILDER_BOOTSTRAP_JS = `
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

    if (ruleBuilderValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(ruleBuilderValueListBody, [row]);
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

    if (ruleBuilderValueListBody instanceof HTMLElement) {
      replaceTableBodyRows(ruleBuilderValueListBody, rows);
    }
  }

  async function loadRuleValueLists(statusElement, options = {}) {
    const quietSuccess = options && options.quietSuccess === true;

    if (statusElement instanceof HTMLElement && !quietSuccess) {
      setStatus(statusElement, 'Loading reusable lists...', false);
    }

    if (ruleBuilderValueListBody instanceof HTMLElement) {
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
`;
