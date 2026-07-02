
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
  const rulesListPath =
    parsedContext && typeof parsedContext.rulesListPath === 'string'
      ? parsedContext.rulesListPath
      : '';
  const badgeRuleApiPath =
    parsedContext && typeof parsedContext.badgeRuleApiPath === 'string'
      ? parsedContext.badgeRuleApiPath
      : '';
  const lmsConnectionsApiPath =
    parsedContext && typeof parsedContext.lmsConnectionsApiPath === 'string'
      ? parsedContext.lmsConnectionsApiPath
      : '';

  if (
    tenantAdminPath.length === 0 ||
    rulesListPath.length === 0 ||
    badgeRuleApiPath.length === 0 ||
    lmsConnectionsApiPath.length === 0
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
  const ruleBuilderLmsConnectionSelect = document.getElementById('rule-builder-lms-connection');
  const ruleBuilderLmsStatus = document.getElementById('rule-builder-lms-status');
  const ruleBuilderLmsProviderKindInput = document.getElementById('rule-builder-lms-provider-kind');
  const ruleBuilderApplyTemplateButton = document.getElementById('rule-builder-apply-template');
  const ruleBuilderAddConditionButton = document.getElementById('rule-builder-add-condition');
  const ruleBuilderAddAlternativePathButton = document.getElementById(
    'rule-builder-add-alternative-path',
  );
  const ruleBuilderRequireEveryRequirementButton = document.getElementById(
    'rule-builder-require-every-requirement',
  );
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
  const ruleBuilderStepNextButton = document.getElementById('rule-builder-step-next');
  const ruleBuilderStepProgress = document.getElementById('rule-builder-step-progress');
  const ruleBuilderStepCallout = document.getElementById('rule-builder-step-callout');
  const ruleBuilderStepFooter = document.getElementById('rule-builder-step-footer');
  const ruleBuilderSubmitButton = document.getElementById('rule-builder-submit');
  const ruleBuilderCanvasCount = document.getElementById('rule-builder-canvas-count');
  const ruleBuilderCanvasLogic = document.getElementById('rule-builder-canvas-logic');
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
  const ruleBuilderSourceList = document.getElementById('rule-builder-source-list');
  const ruleBuilderSourceSample = document.getElementById('rule-builder-source-sample');
  const ruleBuilderStepButtons = Array.from(
    document.querySelectorAll('[data-rule-step-target]'),
  ).filter((candidate) => candidate instanceof HTMLButtonElement);
  const ruleBuilderContext =
    parsedContext &&
    parsedContext.ruleBuilderContext &&
    typeof parsedContext.ruleBuilderContext === 'object'
      ? parsedContext.ruleBuilderContext
      : {};
  const initialRuleValueLists =
    ruleBuilderContext &&
    Array.isArray(ruleBuilderContext.valueLists)
      ? ruleBuilderContext.valueLists
      : [];
  let ruleValueLists = initialRuleValueLists;

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
