export const INSTITUTION_ADMIN_JS = `
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
  const manualIssueApiPath =
    parsedContext && typeof parsedContext.manualIssueApiPath === 'string'
      ? parsedContext.manualIssueApiPath
      : '';
  const createApiKeyPath =
    parsedContext && typeof parsedContext.createApiKeyPath === 'string'
      ? parsedContext.createApiKeyPath
      : '';
  const createOrgUnitPath =
    parsedContext && typeof parsedContext.createOrgUnitPath === 'string'
      ? parsedContext.createOrgUnitPath
      : '';
  const badgeTemplateApiPathPrefix =
    parsedContext && typeof parsedContext.badgeTemplateApiPathPrefix === 'string'
      ? parsedContext.badgeTemplateApiPathPrefix
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
  const badgeRuleReviewQueueApiPath =
    parsedContext && typeof parsedContext.badgeRuleReviewQueueApiPath === 'string'
      ? parsedContext.badgeRuleReviewQueueApiPath
      : '';
  const assertionsApiPathPrefix =
    parsedContext && typeof parsedContext.assertionsApiPathPrefix === 'string'
      ? parsedContext.assertionsApiPathPrefix
      : '';
  const issuedBadgeRowsPath =
    parsedContext && typeof parsedContext.issuedBadgeRowsPath === 'string'
      ? parsedContext.issuedBadgeRowsPath
      : assertionsApiPathPrefix.length === 0
        ? ''
        : assertionsApiPathPrefix + '/table-rows';
  const tenantUsersApiPathPrefix =
    parsedContext && typeof parsedContext.tenantUsersApiPathPrefix === 'string'
      ? parsedContext.tenantUsersApiPathPrefix
      : '';
  const tenantMembersApiPath =
    parsedContext && typeof parsedContext.tenantMembersApiPath === 'string'
      ? parsedContext.tenantMembersApiPath
      : '';
  const authPolicyApiPath =
    parsedContext && typeof parsedContext.authPolicyApiPath === 'string'
      ? parsedContext.authPolicyApiPath
      : '';
  const authProvidersApiPath =
    parsedContext && typeof parsedContext.authProvidersApiPath === 'string'
      ? parsedContext.authProvidersApiPath
      : '';
  const breakGlassAccountsApiPath =
    parsedContext && typeof parsedContext.breakGlassAccountsApiPath === 'string'
      ? parsedContext.breakGlassAccountsApiPath
      : '';

  if (
    tenantAdminPath.length === 0 ||
    manualIssueApiPath.length === 0 ||
    createApiKeyPath.length === 0 ||
    createOrgUnitPath.length === 0 ||
    badgeTemplateApiPathPrefix.length === 0 ||
    badgeRuleApiPath.length === 0 ||
    badgeRuleValueListApiPath.length === 0 ||
    badgeRulePreviewSimulationApiPath.length === 0 ||
    badgeRuleReviewQueueApiPath.length === 0 ||
    assertionsApiPathPrefix.length === 0 ||
    tenantMembersApiPath.length === 0 ||
    tenantUsersApiPathPrefix.length === 0
  ) {
    return;
  }

  const adminButtonTinyClass = 'ct-admin__button ct-admin__button--tiny';
  const adminButtonTinySecondaryClass = adminButtonTinyClass + ' ct-admin__button--secondary';
  const adminButtonTinyGhostClass = adminButtonTinyClass + ' ct-admin__button--ghost';
  const adminButtonTinyDangerClass = adminButtonTinyClass + ' ct-admin__button--danger';
  const badgeTemplateImageQueuedPollDelayMs = 15000;
  const badgeTemplateImageProcessingPollDelayMs = 10000;

  const manualIssueForm = document.getElementById('manual-issue-form');
  const manualIssueStatus = document.getElementById('manual-issue-status');
  const apiKeyForm = document.getElementById('api-key-form');
  const apiKeyStatus = document.getElementById('api-key-status');
  const apiKeySecret = document.getElementById('api-key-secret');
  const orgUnitForm = document.getElementById('org-unit-form');
  const orgUnitStatus = document.getElementById('org-unit-status');
  const templateImagePanel = document.getElementById('template-image-panel');
  const badgeTemplateImageUploadForm = document.getElementById('badge-template-image-upload-form');
  const badgeTemplateImageUploadStatus = document.getElementById(
    'badge-template-image-upload-status',
  );
  const badgeTemplateImageGenerationForm = document.getElementById(
    'badge-template-image-generation-form',
  );
  const badgeTemplateImageGenerationStatus = document.getElementById(
    'badge-template-image-generation-status',
  );
  const badgeTemplateImageGenerationPreview = document.getElementById(
    'badge-template-image-generation-preview',
  );
  const badgeTemplateImageGenerationPreviewImg = document.getElementById(
    'badge-template-image-generation-preview-img',
  );
  const badgeTemplateImageGenerationApplyButton = document.getElementById(
    'badge-template-image-generation-apply',
  );
  const badgeTemplateImageRevisionForm = document.getElementById(
    'badge-template-image-revision-form',
  );
  const badgeTemplateImageRevisionStatus = document.getElementById(
    'badge-template-image-revision-status',
  );
  const badgeTemplateImageRevisionList = document.getElementById(
    'badge-template-image-revision-list',
  );
  const apiKeyRevokeStatus = document.getElementById('api-key-revoke-status');
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
  const ruleBuilderStepPrevButton = document.getElementById('rule-builder-step-prev');
  const ruleBuilderStepNextButton = document.getElementById('rule-builder-step-next');
  const ruleBuilderStepProgress = document.getElementById('rule-builder-step-progress');
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
  const ruleEvaluateForm = document.getElementById('rule-evaluate-form');
  const ruleEvaluateStatus = document.getElementById('rule-evaluate-status');
  const ruleActionStatus = document.getElementById('rule-action-status');
  const ruleValueListForm = document.getElementById('rule-value-list-form');
  const ruleValueListStatus = document.getElementById('rule-value-list-status');
  const ruleValueListBody = document.getElementById('rule-value-list-body');
  const ruleReviewQueueRefreshButton = document.getElementById('rule-review-queue-refresh');
  const ruleReviewQueueStatus = document.getElementById('rule-review-queue-status');
  const ruleReviewQueueBody = document.getElementById('rule-review-queue-body');
  const issuedBadgesFilterForm = document.getElementById('issued-badges-filter-form');
  const issuedBadgesStatus = document.getElementById('issued-badges-status');
  const issuedBadgesBody = document.getElementById('issued-badges-body');
  const issuedBadgesActionStatus = document.getElementById('issued-badges-action-status');
  const reportingFiltersForm = document.getElementById('reporting-filters-form');
  const reportingFiltersStatus = document.getElementById('reporting-filters-status');
  const membershipScopeForm = document.getElementById('membership-scope-form');
  const membershipScopeStatus = document.getElementById('membership-scope-status');
  const membershipScopeBody = document.getElementById('membership-scope-body');
  const membershipScopeListStatus = document.getElementById('membership-scope-list-status');
  const tenantMemberForm = document.getElementById('tenant-member-form');
  const tenantMemberStatus = document.getElementById('tenant-member-status');
  const tenantMemberBody = document.getElementById('tenant-member-body');
  const tenantMemberListStatus = document.getElementById('tenant-member-list-status');
  const delegatedGrantForm = document.getElementById('delegated-grant-form');
  const delegatedGrantStatus = document.getElementById('delegated-grant-status');
  const delegatedGrantBody = document.getElementById('delegated-grant-body');
  const delegatedGrantListStatus = document.getElementById('delegated-grant-list-status');
  const assertionLifecycleViewForm = document.getElementById('assertion-lifecycle-view-form');
  const assertionLifecycleViewStatus = document.getElementById('assertion-lifecycle-view-status');
  const assertionLifecycleOutput = document.getElementById('assertion-lifecycle-output');
  const assertionLifecycleTransitionForm = document.getElementById(
    'assertion-lifecycle-transition-form',
  );
  const assertionLifecycleTransitionStatus = document.getElementById(
    'assertion-lifecycle-transition-status',
  );
  const ruleGovernanceForm = document.getElementById('rule-governance-form');
  const ruleGovernanceStatus = document.getElementById('rule-governance-status');
  const ruleGovernanceOutput = document.getElementById('rule-governance-output');
  const enterpriseAuthPolicyForm = document.getElementById('enterprise-auth-policy-form');
  const enterpriseAuthPolicyStatus = document.getElementById('enterprise-auth-policy-status');
  const enterpriseAuthProviderForm = document.getElementById('enterprise-auth-provider-form');
  const enterpriseAuthProviderStatus = document.getElementById('enterprise-auth-provider-status');
  const enterpriseAuthProviderBody = document.getElementById('enterprise-auth-provider-body');
  const enterpriseAuthProviderResetButton = document.getElementById('enterprise-auth-provider-reset');
  const breakGlassAccountForm = document.getElementById('break-glass-account-form');
  const breakGlassAccountStatus = document.getElementById('break-glass-account-status');
  const breakGlassAccountBody = document.getElementById('break-glass-account-body');
  let ruleValueLists = [];
  let refreshIssuedBadges = null;
  let activeBadgeTemplateImageGeneration = null;
  let badgeTemplateImageGenerationPollTimer = null;

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
  const toCommaSeparatedList = (value) => {
    return typeof value !== 'string'
      ? []
      : value
          .split(',')
          .map((entry) => entry.trim())
          .filter((entry) => entry.length > 0);
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
  const reloadCurrentPage = () => {
    window.location.assign(window.location.pathname + window.location.search);
  };
  const escapeHtml = (value) => {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  };
  const createAdminButtonElement = (className, label, attributes) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;

    Object.entries(attributes || {}).forEach(([name, value]) => {
      button.setAttribute(name, String(value));
    });

    return button;
  };
  const formatTimestamp = (value) => {
    if (typeof value !== 'string' || value.length === 0) {
      return 'n/a';
    }

    const parsed = Date.parse(value);

    if (!Number.isFinite(parsed)) {
      return value;
    }

    return new Date(parsed).toLocaleString();
  };
  const badgeTemplateImageGenerationPath = (badgeTemplateId, generationId) => {
    return (
      badgeTemplateApiPathPrefix +
      '/' +
      encodeURIComponent(badgeTemplateId) +
      '/image-generations/' +
      encodeURIComponent(generationId)
    );
  };
  const clearBadgeTemplateImageGenerationPoll = () => {
    if (badgeTemplateImageGenerationPollTimer !== null) {
      window.clearTimeout(badgeTemplateImageGenerationPollTimer);
      badgeTemplateImageGenerationPollTimer = null;
    }
  };
  const showBadgeTemplateImageGenerationPreview = (generation) => {
    if (
      !(badgeTemplateImageGenerationPreview instanceof HTMLElement) ||
      !(badgeTemplateImageGenerationPreviewImg instanceof HTMLImageElement) ||
      !(badgeTemplateImageGenerationApplyButton instanceof HTMLButtonElement)
    ) {
      return;
    }

    if (
      !generation ||
      generation.status !== 'succeeded' ||
      typeof generation.resultImageUri !== 'string' ||
      generation.resultImageUri.length === 0
    ) {
      badgeTemplateImageGenerationPreview.hidden = true;
      badgeTemplateImageGenerationPreviewImg.removeAttribute('src');
      badgeTemplateImageGenerationApplyButton.disabled = true;
      return;
    }

    badgeTemplateImageGenerationPreview.hidden = false;
    badgeTemplateImageGenerationPreviewImg.src = generation.resultImageUri;
    badgeTemplateImageGenerationApplyButton.disabled = false;
  };
  const pollBadgeTemplateImageGeneration = async (badgeTemplateId, generationId) => {
    if (!(badgeTemplateImageGenerationStatus instanceof HTMLElement)) {
      return;
    }

    try {
      const response = await fetch(badgeTemplateImageGenerationPath(badgeTemplateId, generationId));
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      const generation = payload && payload.generation ? payload.generation : null;
      activeBadgeTemplateImageGeneration = {
        badgeTemplateId,
        generationId,
      };

      if (generation && generation.status === 'succeeded') {
        setStatus(badgeTemplateImageGenerationStatus, 'Generated draft ready.', false, 'success');
        showBadgeTemplateImageGenerationPreview(generation);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      if (generation && generation.status === 'failed') {
        const detail =
          typeof generation.errorMessage === 'string' && generation.errorMessage.length > 0
            ? generation.errorMessage
            : 'Badge image generation failed.';
        setStatus(badgeTemplateImageGenerationStatus, detail, true);
        showBadgeTemplateImageGenerationPreview(null);
        clearBadgeTemplateImageGenerationPoll();
        return;
      }

      const status = generation && typeof generation.status === 'string' ? generation.status : '';
      const statusText =
        status === 'queued'
          ? 'Draft queued. Waiting for the background image worker...'
          : 'Generating badge image draft. Checking again shortly...';
      const nextPollDelayMs =
        status === 'processing'
          ? badgeTemplateImageProcessingPollDelayMs
          : badgeTemplateImageQueuedPollDelayMs;

      setStatus(badgeTemplateImageGenerationStatus, statusText, false);
      badgeTemplateImageGenerationPollTimer = window.setTimeout(() => {
        void pollBadgeTemplateImageGeneration(badgeTemplateId, generationId);
      }, nextPollDelayMs);
    } catch {
      setStatus(
        badgeTemplateImageGenerationStatus,
        'Unable to check badge image generation status from this browser session.',
        true,
      );
      clearBadgeTemplateImageGenerationPoll();
    }
  };
  const renderBadgeTemplateImageRevisions = (badgeTemplateId, revisions) => {
    if (!(badgeTemplateImageRevisionList instanceof HTMLElement)) {
      return;
    }

    badgeTemplateImageRevisionList.textContent = '';

    if (!Array.isArray(revisions) || revisions.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'ct-admin__empty';
      empty.textContent = 'No image history is available for this badge template.';
      badgeTemplateImageRevisionList.append(empty);
      return;
    }

    revisions.forEach((revision) => {
      const item = document.createElement('div');
      item.className = 'ct-admin__image-revision-item';
      const meta = document.createElement('div');
      meta.className = 'ct-admin__image-revision-meta';
      const title = document.createElement('strong');
      title.textContent =
        String(revision.sourceType || 'image change') + ' · ' + formatTimestamp(revision.createdAt);
      const detail = document.createElement('span');
      detail.textContent =
        typeof revision.previousImageUri === 'string' && revision.previousImageUri.length > 0
          ? 'Restore the previous image'
          : 'Restore to no image';
      meta.append(title, detail);

      const button = createAdminButtonElement(adminButtonTinySecondaryClass, 'Restore', {
        'data-badge-template-id': badgeTemplateId,
        'data-revision-id': String(revision.id || ''),
      });

      item.append(meta, button);
      badgeTemplateImageRevisionList.append(item);
    });
  };
  const loadBadgeTemplateImageRevisions = async (badgeTemplateId) => {
    if (!(badgeTemplateImageRevisionStatus instanceof HTMLElement)) {
      return;
    }

    if (badgeTemplateId.length === 0) {
      setStatus(badgeTemplateImageRevisionStatus, 'Badge template is required.', true);
      return;
    }

    setStatus(badgeTemplateImageRevisionStatus, 'Loading badge image history...', false);

    try {
      const response = await fetch(
        badgeTemplateApiPathPrefix +
          '/' +
          encodeURIComponent(badgeTemplateId) +
          '/image-revisions',
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(badgeTemplateImageRevisionStatus, errorDetailFromPayload(payload), true);
        return;
      }

      renderBadgeTemplateImageRevisions(
        badgeTemplateId,
        payload && Array.isArray(payload.revisions) ? payload.revisions : [],
      );
      setStatus(badgeTemplateImageRevisionStatus, 'Image history loaded.', false, 'success');
    } catch {
      setStatus(
        badgeTemplateImageRevisionStatus,
        'Unable to load badge image history from this browser session.',
        true,
      );
    }
  };
  const parseIssuedBadgesLimit = (rawValue) => {
    const fallbackLimit = 100;

    if (typeof rawValue !== 'string') {
      return fallbackLimit;
    }

    const parsed = Number(rawValue.trim());

    if (!Number.isFinite(parsed)) {
      return fallbackLimit;
    }

    return Math.max(1, Math.min(500, Math.trunc(parsed)));
  };
  const fillLifecycleAssertionIdInputs = (assertionId) => {
    if (typeof assertionId !== 'string' || assertionId.length === 0) {
      return;
    }

    if (assertionLifecycleViewForm instanceof HTMLFormElement) {
      const lifecycleInput = assertionLifecycleViewForm.elements.namedItem('assertionId');

      if (lifecycleInput instanceof HTMLInputElement) {
        lifecycleInput.value = assertionId;
      }
    }

    if (assertionLifecycleTransitionForm instanceof HTMLFormElement) {
      const transitionInput = assertionLifecycleTransitionForm.elements.namedItem('assertionId');

      if (transitionInput instanceof HTMLInputElement) {
        transitionInput.value = assertionId;
      }
    }
  };
  const fillEnterpriseAuthProviderForm = (provider) => {
    if (!(enterpriseAuthProviderForm instanceof HTMLFormElement) || provider === null) {
      return;
    }

    const providerIdInput = enterpriseAuthProviderForm.elements.namedItem('providerId');
    const protocolInput = enterpriseAuthProviderForm.elements.namedItem('protocol');
    const labelInput = enterpriseAuthProviderForm.elements.namedItem('label');
    const enabledInput = enterpriseAuthProviderForm.elements.namedItem('enabled');
    const isDefaultInput = enterpriseAuthProviderForm.elements.namedItem('isDefault');
    const configJsonInput = enterpriseAuthProviderForm.elements.namedItem('configJson');

    if (providerIdInput instanceof HTMLInputElement) {
      providerIdInput.value = typeof provider.id === 'string' ? provider.id : '';
    }

    if (protocolInput instanceof HTMLInputElement || protocolInput instanceof HTMLSelectElement) {
      protocolInput.value = typeof provider.protocol === 'string' ? provider.protocol : 'oidc';
    }

    if (labelInput instanceof HTMLInputElement) {
      labelInput.value = typeof provider.label === 'string' ? provider.label : '';
    }

    if (enabledInput instanceof HTMLInputElement) {
      enabledInput.checked = provider.enabled === true;
    }

    if (isDefaultInput instanceof HTMLInputElement) {
      isDefaultInput.checked = provider.isDefault === true;
    }

    if (configJsonInput instanceof HTMLTextAreaElement) {
      configJsonInput.value = typeof provider.configJson === 'string' ? provider.configJson : '{}';
    }
  };
  const resetEnterpriseAuthProviderForm = () => {
    if (!(enterpriseAuthProviderForm instanceof HTMLFormElement)) {
      return;
    }

    enterpriseAuthProviderForm.reset();

    const providerIdInput = enterpriseAuthProviderForm.elements.namedItem('providerId');
    const protocolInput = enterpriseAuthProviderForm.elements.namedItem('protocol');
    const enabledInput = enterpriseAuthProviderForm.elements.namedItem('enabled');
    const isDefaultInput = enterpriseAuthProviderForm.elements.namedItem('isDefault');
    const configJsonInput = enterpriseAuthProviderForm.elements.namedItem('configJson');

    if (providerIdInput instanceof HTMLInputElement) {
      providerIdInput.value = '';
    }

    if (protocolInput instanceof HTMLInputElement || protocolInput instanceof HTMLSelectElement) {
      protocolInput.value = 'oidc';
    }

    if (enabledInput instanceof HTMLInputElement) {
      enabledInput.checked = true;
    }

    if (isDefaultInput instanceof HTMLInputElement) {
      isDefaultInput.checked = false;
    }

    if (configJsonInput instanceof HTMLTextAreaElement) {
      configJsonInput.value = '';
    }
  };
  const setIssuedBadgesEmptyState = (message) => {
    if (!(issuedBadgesBody instanceof HTMLElement)) {
      return;
    }

    issuedBadgesBody.innerHTML =
      '<tr><td colspan="6" class="ct-admin__empty">' + escapeHtml(message) + '</td></tr>';
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

  function summarizeReviewQueueEntry(entry) {
    const summary =
      entry &&
      entry.evaluationSummary &&
      typeof entry.evaluationSummary === 'object'
        ? entry.evaluationSummary
        : null;
    const parts = [];

    if (summary && typeof summary.matchedLeafCount === 'number') {
      parts.push(String(summary.matchedLeafCount) + ' matched');
    }

    if (summary && typeof summary.failedConditionCount === 'number') {
      parts.push(String(summary.failedConditionCount) + ' failed');
    }

    if (summary && typeof summary.missingDataCount === 'number') {
      parts.push(String(summary.missingDataCount) + ' missing');
    }

    if (parts.length === 0) {
      return 'Awaiting manual review';
    }

    return parts.join(' · ');
  }

  function setRuleReviewQueueEmptyState(message) {
    if (!(ruleReviewQueueBody instanceof HTMLElement)) {
      return;
    }

    replaceTableBodyRows(ruleReviewQueueBody, [createEmptyTableRow(5, message)]);
  }

  function createReviewQueueRow(entry) {
    const evaluationId =
      entry && typeof entry.id === 'string' ? entry.id : '';
    const evaluatedAt =
      entry && typeof entry.evaluatedAt === 'string' ? entry.evaluatedAt : '';
    const recipientIdentity =
      entry && typeof entry.recipientIdentity === 'string'
        ? entry.recipientIdentity
        : 'unknown';
    const learnerId =
      entry && typeof entry.learnerId === 'string' ? entry.learnerId : 'unknown';
    const ruleId =
      entry && typeof entry.ruleId === 'string' ? entry.ruleId : 'unknown rule';
    const ruleName =
      entry && typeof entry.ruleName === 'string' && entry.ruleName.length > 0
        ? entry.ruleName
        : ruleId;
    const versionId =
      entry && typeof entry.versionId === 'string' ? entry.versionId : '';
    const badgeTemplateId =
      entry && typeof entry.badgeTemplateId === 'string' ? entry.badgeTemplateId : '';
    const reviewStatus =
      entry && typeof entry.reviewStatus === 'string' ? entry.reviewStatus : 'pending';
    const canResolve = reviewStatus === 'pending' && evaluationId.length > 0;
    const row = document.createElement('tr');
    const evaluatedAtCell = document.createElement('td');
    const recipientCell = document.createElement('td');
    const recipientStrong = document.createElement('strong');
    const learnerMeta = document.createElement('div');
    const ruleCell = document.createElement('td');
    const ruleStrong = document.createElement('strong');
    const ruleMeta = document.createElement('div');
    const summaryCell = document.createElement('td');
    const actionsCell = document.createElement('td');
    const actions = document.createElement('div');

    evaluatedAtCell.textContent = formatTimestamp(evaluatedAt);
    recipientStrong.textContent = recipientIdentity;
    learnerMeta.className = 'ct-admin__meta';
    learnerMeta.textContent = learnerId;
    recipientCell.append(recipientStrong, learnerMeta);
    ruleStrong.textContent = ruleName;
    ruleMeta.className = 'ct-admin__meta';
    ruleMeta.textContent =
      ruleId +
      (badgeTemplateId.length > 0 ? ' · template ' + badgeTemplateId : '') +
      (versionId.length > 0 ? ' · ' + versionId : '');
    ruleCell.append(ruleStrong, ruleMeta);
    summaryCell.textContent = summarizeReviewQueueEntry(entry);
    actions.className = 'ct-admin__actions';

    if (canResolve) {
      actions.append(
        createAdminButtonElement(adminButtonTinyClass, 'Issue badge', {
          'data-review-queue-action': 'issue',
          'data-evaluation-id': evaluationId,
          'data-recipient-identity': recipientIdentity,
        }),
        createAdminButtonElement(adminButtonTinySecondaryClass, 'Dismiss', {
          'data-review-queue-action': 'dismiss',
          'data-evaluation-id': evaluationId,
          'data-recipient-identity': recipientIdentity,
        }),
      );
    } else {
      const resolved = document.createElement('span');
      resolved.className = 'ct-admin__meta';
      resolved.textContent = 'Resolved';
      actions.appendChild(resolved);
    }

    actionsCell.appendChild(actions);
    row.append(evaluatedAtCell, recipientCell, ruleCell, summaryCell, actionsCell);

    return row;
  }

  function renderRuleReviewQueueRows(queue) {
    if (!(ruleReviewQueueBody instanceof HTMLElement)) {
      return;
    }

    if (!Array.isArray(queue) || queue.length === 0) {
      setRuleReviewQueueEmptyState('No pending review queue entries.');
      return;
    }

    replaceTableBodyRows(
      ruleReviewQueueBody,
      queue.map((entry) => createReviewQueueRow(entry)),
    );
  }

  async function loadRuleReviewQueue() {
    if (!(ruleReviewQueueStatus instanceof HTMLElement)) {
      return [];
    }

    setStatus(ruleReviewQueueStatus, 'Loading review queue...', false);
    setRuleReviewQueueEmptyState('Loading review queue...');

    try {
      const query = new URLSearchParams({
        status: 'pending',
        limit: '50',
      });
      const response = await fetch(badgeRuleReviewQueueApiPath + '?' + query.toString());
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(ruleReviewQueueStatus, errorDetailFromPayload(payload), true);
        setRuleReviewQueueEmptyState('Unable to load review queue.');
        return [];
      }

      const queue = payload && Array.isArray(payload.queue) ? payload.queue : [];
      renderRuleReviewQueueRows(queue);
      setStatus(
        ruleReviewQueueStatus,
        queue.length === 0
          ? 'No pending review queue entries.'
          : 'Loaded ' +
              String(queue.length) +
              ' pending review entr' +
              (queue.length === 1 ? 'y' : 'ies') +
              '.',
        false,
        queue.length === 0 ? 'info' : 'success',
      );
      return queue;
    } catch {
      setStatus(ruleReviewQueueStatus, 'Unable to load review queue from this browser session.', true);
      setRuleReviewQueueEmptyState('Unable to load review queue.');
      return [];
    }
  }

  async function resolveReviewQueueEntry(decision, evaluationId, recipientIdentity) {
    if (!(ruleReviewQueueStatus instanceof HTMLElement)) {
      return;
    }

    if (
      (decision !== 'issue' && decision !== 'dismiss') ||
      typeof evaluationId !== 'string' ||
      evaluationId.trim().length === 0
    ) {
      setStatus(ruleReviewQueueStatus, 'Invalid review queue action.', true);
      return;
    }

    const trimmedEvaluationId = evaluationId.trim();
    const trimmedRecipientIdentity =
      typeof recipientIdentity === 'string' ? recipientIdentity.trim() : 'recipient';
    const actionLabel = decision === 'issue' ? 'issue' : 'dismiss';
    const commentPrompt = window.prompt(
      'Optional comment for ' +
        actionLabel +
        ' decision on ' +
        trimmedRecipientIdentity +
        ':',
      decision === 'issue' ? 'Manual review approved by issuer' : 'Missing facts confirmed; no issue',
    );

    if (commentPrompt === null) {
      return;
    }

    setStatus(
      ruleReviewQueueStatus,
      (decision === 'issue' ? 'Issuing' : 'Dismissing') +
        ' review queue entry ' +
        trimmedEvaluationId +
        '...',
      false,
    );

    try {
      const response = await fetch(
        badgeRuleReviewQueueApiPath + '/' + encodeURIComponent(trimmedEvaluationId) + '/resolve',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            decision,
            ...(commentPrompt.trim().length > 0 ? { comment: commentPrompt.trim() } : {}),
          }),
        },
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(ruleReviewQueueStatus, errorDetailFromPayload(payload), true);
        return;
      }

      setStatus(
        ruleReviewQueueStatus,
        (decision === 'issue' ? 'Issued badge' : 'Dismissed review') +
          ' for ' +
          trimmedRecipientIdentity +
          '.',
        false,
        decision === 'issue' ? 'success' : 'warning',
      );
      await loadRuleReviewQueue();

      if (typeof refreshIssuedBadges === 'function') {
        await refreshIssuedBadges();
      }
    } catch {
      setStatus(
        ruleReviewQueueStatus,
        'Unable to resolve review queue entry from this browser session.',
        true,
      );
    }
  }

  const loadAssertionLifecycle = async (assertionId, statusElement) => {
    const normalizedAssertionId =
      typeof assertionId === 'string' ? assertionId.trim() : '';

    if (normalizedAssertionId.length === 0) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Assertion ID is required.', true);
      }

      return null;
    }

    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, 'Loading lifecycle state...', false);
    }

    setCodeOutput(assertionLifecycleOutput, '');

    try {
      const response = await fetch(
        assertionsApiPathPrefix + '/' + encodeURIComponent(normalizedAssertionId) + '/lifecycle',
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        if (statusElement instanceof HTMLElement) {
          setStatus(statusElement, errorDetailFromPayload(payload), true);
        }

        return null;
      }

      const state = payload && typeof payload.state === 'string' ? payload.state : 'unknown';
      const source = payload && typeof payload.source === 'string' ? payload.source : 'unknown';
      const eventCount = payload && Array.isArray(payload.events) ? payload.events.length : 0;

      if (statusElement instanceof HTMLElement) {
        setStatus(
          statusElement,
          'Lifecycle loaded: state=' +
            state +
            ', source=' +
            source +
            ', events=' +
            String(eventCount) +
            '.',
          false,
        );
      }

      setCodeOutput(assertionLifecycleOutput, JSON.stringify(payload, null, 2));
      fillLifecycleAssertionIdInputs(normalizedAssertionId);
      return payload;
    } catch {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Unable to load lifecycle state from this browser session.', true);
      }

      return null;
    }
  };

  if (ruleValueListForm instanceof HTMLFormElement && ruleValueListStatus instanceof HTMLElement) {
    ruleValueListForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(ruleValueListStatus, 'Creating reusable list...', false);
      const data = new FormData(ruleValueListForm);
      const labelRaw = data.get('label');
      const kindRaw = data.get('kind');
      const valuesRaw = data.get('values');
      const label = typeof labelRaw === 'string' ? labelRaw.trim() : '';
      const kind = typeof kindRaw === 'string' ? kindRaw.trim() : '';
      const values = toCommaSeparatedList(valuesRaw);

      if (label.length === 0 || kind.length === 0 || values.length === 0) {
        setStatus(ruleValueListStatus, 'Label, kind, and at least one value are required.', true);
        return;
      }

      try {
        const response = await fetch(badgeRuleValueListApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            label,
            kind,
            values,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(ruleValueListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        ruleValueListForm.reset();
        setStatus(ruleValueListStatus, 'Reusable list created.', false, 'success');
        await loadRuleValueLists(ruleValueListStatus, {
          quietSuccess: true,
        });
      } catch {
        setStatus(ruleValueListStatus, 'Unable to create reusable list from this browser session.', true);
      }
    });
  }

  if (ruleReviewQueueRefreshButton instanceof HTMLButtonElement) {
    ruleReviewQueueRefreshButton.addEventListener('click', async () => {
      await loadRuleReviewQueue();
    });
  }

  if (ruleReviewQueueBody instanceof HTMLElement) {
    ruleReviewQueueBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const actionButton = target.closest('button[data-review-queue-action]');

      if (!(actionButton instanceof HTMLButtonElement)) {
        return;
      }

      const decision = actionButton.dataset.reviewQueueAction;
      const evaluationId = actionButton.dataset.evaluationId ?? '';
      const recipientIdentity = actionButton.dataset.recipientIdentity ?? '';

      if (decision !== 'issue' && decision !== 'dismiss') {
        setStatus(ruleReviewQueueStatus, 'Invalid review queue action.', true);
        return;
      }

      const confirmed = window.confirm(
        (decision === 'issue' ? 'Issue badge for ' : 'Dismiss review for ') +
          (recipientIdentity.length > 0 ? recipientIdentity : evaluationId) +
          '?',
      );

      if (!confirmed) {
        return;
      }

      await resolveReviewQueueEntry(decision, evaluationId, recipientIdentity);
    });
  }

  if (ruleValueListBody instanceof HTMLElement || ruleBuilderValueListBody instanceof HTMLElement) {
    void loadRuleValueLists(ruleValueListStatus, {
      quietSuccess: !(ruleValueListStatus instanceof HTMLElement),
    });
  }

  if (ruleReviewQueueBody instanceof HTMLElement) {
    void loadRuleReviewQueue();
  }

  if (manualIssueForm instanceof HTMLFormElement && manualIssueStatus instanceof HTMLElement) {
    manualIssueForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(manualIssueStatus, 'Issuing badge...', false);
      const data = new FormData(manualIssueForm);
      const recipientIdentityRaw = data.get('recipientIdentity');
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const recipientIdentity =
        typeof recipientIdentityRaw === 'string' ? recipientIdentityRaw.trim().toLowerCase() : '';
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';

      if (recipientIdentity.length === 0 || badgeTemplateId.length === 0) {
        setStatus(manualIssueStatus, 'Recipient email and badge template are required.', true);
        return;
      }

      try {
        const response = await fetch(manualIssueApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            badgeTemplateId,
            recipientIdentity,
            recipientIdentityType: 'email',
            recipientIdentifiers: [
              {
                identifierType: 'emailAddress',
                identifier: recipientIdentity,
              },
            ],
          }),
        });

        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(manualIssueStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const assertionId =
          payload && typeof payload.assertionId === 'string' ? payload.assertionId : null;
        const link =
          assertionId === null
            ? ''
            : ' Open /badges/' + assertionId + ' (redirects to canonical URL).';
        setStatus(manualIssueStatus, 'Badge issued for ' + recipientIdentity + '.' + link, false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(manualIssueStatus, 'Unable to issue badge from this browser session.', true);
      }
    });
  }

  if (
    apiKeyForm instanceof HTMLFormElement &&
    apiKeyStatus instanceof HTMLElement &&
    apiKeySecret instanceof HTMLElement
  ) {
    apiKeyForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(apiKeyStatus, 'Creating API key...', false);
      apiKeySecret.hidden = true;
      apiKeySecret.textContent = '';

      const data = new FormData(apiKeyForm);
      const labelRaw = data.get('label');
      const scopesRaw = data.get('scopes');
      const label = typeof labelRaw === 'string' ? labelRaw.trim() : '';
      const scopeList =
        typeof scopesRaw !== 'string'
          ? []
          : scopesRaw
              .split(',')
              .map((entry) => entry.trim())
              .filter((entry) => entry.length > 0);

      if (label.length === 0) {
        setStatus(apiKeyStatus, 'Label is required.', true);
        return;
      }

      try {
        const response = await fetch(createApiKeyPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            label,
            scopes: scopeList,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(apiKeyStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const apiKey = payload && typeof payload.apiKey === 'string' ? payload.apiKey : null;

        if (apiKey !== null) {
          apiKeySecret.hidden = false;
          apiKeySecret.textContent = 'Store this now. It is shown once:\\n\\n' + apiKey;
        }

        setStatus(apiKeyStatus, 'API key created.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(apiKeyStatus, 'Unable to create API key from this browser session.', true);
      }
    });
  }

  if (
    enterpriseAuthPolicyForm instanceof HTMLFormElement &&
    enterpriseAuthPolicyStatus instanceof HTMLElement &&
    authPolicyApiPath.length > 0
  ) {
    enterpriseAuthPolicyForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(enterpriseAuthPolicyStatus, 'Saving auth policy...', false);

      const data = new FormData(enterpriseAuthPolicyForm);
      const loginModeRaw = data.get('loginMode');
      const defaultProviderIdRaw = data.get('defaultProviderId');
      const loginMode = typeof loginModeRaw === 'string' ? loginModeRaw.trim() : '';
      const defaultProviderId =
        typeof defaultProviderIdRaw === 'string' ? defaultProviderIdRaw.trim() : '';

      if (loginMode.length === 0) {
        setStatus(enterpriseAuthPolicyStatus, 'Login mode is required.', true);
        return;
      }

      try {
        const response = await fetch(authPolicyApiPath, {
          method: 'PUT',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            loginMode,
            breakGlassEnabled: data.get('breakGlassEnabled') !== null,
            localMfaRequired: data.get('localMfaRequired') !== null,
            defaultProviderId: defaultProviderId.length > 0 ? defaultProviderId : null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthPolicyStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(enterpriseAuthPolicyStatus, 'Enterprise auth policy saved.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthPolicyStatus, 'Unable to save enterprise auth policy.', true);
      }
    });
  }

  if (
    enterpriseAuthProviderForm instanceof HTMLFormElement &&
    enterpriseAuthProviderStatus instanceof HTMLElement &&
    authProvidersApiPath.length > 0
  ) {
    enterpriseAuthProviderForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(enterpriseAuthProviderStatus, 'Saving auth provider...', false);

      const data = new FormData(enterpriseAuthProviderForm);
      const providerIdRaw = data.get('providerId');
      const protocolRaw = data.get('protocol');
      const labelRaw = data.get('label');
      const configJsonRaw = data.get('configJson');
      const providerId = typeof providerIdRaw === 'string' ? providerIdRaw.trim() : '';
      const protocol = typeof protocolRaw === 'string' ? protocolRaw.trim() : '';
      const label = typeof labelRaw === 'string' ? labelRaw.trim() : '';
      const configJson = typeof configJsonRaw === 'string' ? configJsonRaw.trim() : '';

      if (protocol.length === 0 || label.length === 0 || configJson.length === 0) {
        setStatus(enterpriseAuthProviderStatus, 'Protocol, label, and config JSON are required.', true);
        return;
      }

      const method = providerId.length > 0 ? 'PUT' : 'POST';
      const requestPath =
        method === 'PUT'
          ? authProvidersApiPath + '/' + encodeURIComponent(providerId)
          : authProvidersApiPath;

      try {
        const response = await fetch(requestPath, {
          method,
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            protocol,
            label,
            enabled: data.get('enabled') !== null,
            isDefault: data.get('isDefault') !== null,
            configJson,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthProviderStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(
          enterpriseAuthProviderStatus,
          providerId.length > 0 ? 'Enterprise auth provider updated.' : 'Enterprise auth provider created.',
          false,
        );
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthProviderStatus, 'Unable to save enterprise auth provider.', true);
      }
    });
  }

  if (
    enterpriseAuthProviderResetButton instanceof HTMLButtonElement &&
    enterpriseAuthProviderForm instanceof HTMLFormElement
  ) {
    enterpriseAuthProviderResetButton.addEventListener('click', () => {
      resetEnterpriseAuthProviderForm();
    });
  }

  if (
    enterpriseAuthProviderBody instanceof HTMLElement &&
    enterpriseAuthProviderStatus instanceof HTMLElement &&
    authProvidersApiPath.length > 0
  ) {
    enterpriseAuthProviderBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const editButton = target.closest('[data-enterprise-auth-edit-provider]');

      if (editButton instanceof HTMLElement) {
        fillEnterpriseAuthProviderForm({
          id: editButton.dataset.providerId ?? '',
          protocol: editButton.dataset.providerProtocol ?? 'oidc',
          label: editButton.dataset.providerLabel ?? '',
          enabled: editButton.dataset.providerEnabled === 'true',
          isDefault: editButton.dataset.providerIsDefault === 'true',
          configJson: editButton.dataset.providerConfigJson ?? '{}',
        });
        setStatus(enterpriseAuthProviderStatus, 'Loaded provider into edit form.', false);
        return;
      }

      const deleteButton = target.closest('[data-enterprise-auth-delete-provider-id]');

      if (!(deleteButton instanceof HTMLElement)) {
        return;
      }

      const providerId = deleteButton.dataset.enterpriseAuthDeleteProviderId ?? '';
      const providerLabel = deleteButton.dataset.providerLabel ?? 'this provider';

      if (providerId.length === 0) {
        setStatus(enterpriseAuthProviderStatus, 'Provider ID missing from delete action.', true);
        return;
      }

      if (!window.confirm('Delete ' + providerLabel + '?')) {
        return;
      }

      setStatus(enterpriseAuthProviderStatus, 'Deleting auth provider...', false);

      try {
        const response = await fetch(authProvidersApiPath + '/' + encodeURIComponent(providerId), {
          method: 'DELETE',
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(enterpriseAuthProviderStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(enterpriseAuthProviderStatus, 'Enterprise auth provider deleted.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(enterpriseAuthProviderStatus, 'Unable to delete enterprise auth provider.', true);
      }
    });
  }

  if (
    breakGlassAccountForm instanceof HTMLFormElement &&
    breakGlassAccountStatus instanceof HTMLElement &&
    breakGlassAccountsApiPath.length > 0
  ) {
    breakGlassAccountForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(breakGlassAccountStatus, 'Adding break-glass account...', false);

      const data = new FormData(breakGlassAccountForm);
      const emailRaw = data.get('email');
      const email = typeof emailRaw === 'string' ? emailRaw.trim() : '';

      if (email.length === 0) {
        setStatus(breakGlassAccountStatus, 'Institution email is required.', true);
        return;
      }

      try {
        const response = await fetch(breakGlassAccountsApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            email,
            sendEnrollmentEmail: data.get('sendEnrollmentEmail') !== null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(breakGlassAccountStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(breakGlassAccountStatus, 'Break-glass account saved.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(breakGlassAccountStatus, 'Unable to save break-glass account.', true);
      }
    });
  }

  if (
    breakGlassAccountBody instanceof HTMLElement &&
    breakGlassAccountStatus instanceof HTMLElement &&
    breakGlassAccountsApiPath.length > 0
  ) {
    breakGlassAccountBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const deleteButton = target.closest('[data-break-glass-delete-user-id]');

      if (!(deleteButton instanceof HTMLElement)) {
        return;
      }

      const userId = deleteButton.dataset.breakGlassDeleteUserId ?? '';
      const email = deleteButton.dataset.breakGlassEmail ?? 'this account';

      if (userId.length === 0) {
        setStatus(breakGlassAccountStatus, 'Break-glass user ID missing from revoke action.', true);
        return;
      }

      if (!window.confirm('Revoke break-glass access for ' + email + '?')) {
        return;
      }

      setStatus(breakGlassAccountStatus, 'Revoking break-glass account...', false);

      try {
        const response = await fetch(
          breakGlassAccountsApiPath + '/' + encodeURIComponent(userId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(breakGlassAccountStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(breakGlassAccountStatus, 'Break-glass account revoked.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(breakGlassAccountStatus, 'Unable to revoke break-glass account.', true);
      }
    });
  }

  if (orgUnitForm instanceof HTMLFormElement && orgUnitStatus instanceof HTMLElement) {
    const unitTypeInput = orgUnitForm.elements.namedItem('unitType');
    const parentOrgUnitInput = orgUnitForm.elements.namedItem('parentOrgUnitId');
    const requiredParentTypeByUnitType = {
      institution: null,
      college: 'institution',
      department: 'college',
      program: 'department',
    };

    const syncParentOptions = () => {
      if (!(unitTypeInput instanceof HTMLSelectElement)) {
        return;
      }

      if (!(parentOrgUnitInput instanceof HTMLSelectElement)) {
        return;
      }

      const unitType = unitTypeInput.value;
      const requiredParentType = requiredParentTypeByUnitType[unitType];

      Array.from(parentOrgUnitInput.options).forEach((option) => {
        if (option.value.length === 0) {
          option.hidden = false;
          option.disabled = false;
          option.textContent = requiredParentType === null ? 'None' : 'Select parent';
          return;
        }

        const parentType = option.dataset.unitType ?? null;
        const matches = requiredParentType === null || parentType === requiredParentType;
        option.hidden = !matches;
        option.disabled = !matches;
      });

      const selected = parentOrgUnitInput.selectedOptions.item(0);

      if (selected !== null && selected.value.length > 0 && (selected.hidden || selected.disabled)) {
        parentOrgUnitInput.value = '';
      }
    };

    syncParentOptions();

    if (unitTypeInput instanceof HTMLSelectElement) {
      unitTypeInput.addEventListener('change', syncParentOptions);
    }

    orgUnitForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(orgUnitStatus, 'Creating org unit...', false);
      const data = new FormData(orgUnitForm);
      const unitTypeRaw = data.get('unitType');
      const slugRaw = data.get('slug');
      const displayNameRaw = data.get('displayName');
      const parentOrgUnitIdRaw = data.get('parentOrgUnitId');
      const unitType = typeof unitTypeRaw === 'string' ? unitTypeRaw.trim() : '';
      const slug = typeof slugRaw === 'string' ? slugRaw.trim() : '';
      const displayName = typeof displayNameRaw === 'string' ? displayNameRaw.trim() : '';
      const parentOrgUnitId =
        typeof parentOrgUnitIdRaw === 'string' ? parentOrgUnitIdRaw.trim() : '';

      if (unitType.length === 0 || slug.length === 0 || displayName.length === 0) {
        setStatus(orgUnitStatus, 'Unit type, slug, and display name are required.', true);
        return;
      }

      const requiredParentType = requiredParentTypeByUnitType[unitType] ?? null;

      if (requiredParentType !== null && parentOrgUnitId.length === 0) {
        setStatus(orgUnitStatus, 'Selected unit type requires a parent org unit.', true);
        return;
      }

      try {
        const response = await fetch(createOrgUnitPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            unitType,
            slug,
            displayName,
            ...(parentOrgUnitId.length > 0 ? { parentOrgUnitId } : {}),
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(orgUnitStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(orgUnitStatus, 'Org unit created.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 900);
      } catch {
        setStatus(orgUnitStatus, 'Unable to create org unit from this browser session.', true);
      }
    });
  }

  if (
    badgeTemplateImageUploadForm instanceof HTMLFormElement &&
    badgeTemplateImageUploadStatus instanceof HTMLElement
  ) {
    badgeTemplateImageUploadForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(badgeTemplateImageUploadStatus, 'Uploading template image...', false);
      const data = new FormData(badgeTemplateImageUploadForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const upload = data.get('file');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';

      if (badgeTemplateId.length === 0 || !(upload instanceof File)) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Badge template and image file are required.',
          true,
        );
        return;
      }

      if (upload.size > 2 * 1024 * 1024) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Image file exceeds 2 MB limit.',
          true,
        );
        return;
      }

      const normalizedMimeType = upload.type.trim().toLowerCase();
      const allowedMimeTypes = new Set(['image/png', 'image/jpeg', 'image/webp']);

      if (!allowedMimeTypes.has(normalizedMimeType)) {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Unsupported image type. Use PNG, JPEG, or WebP.',
          true,
        );
        return;
      }

      const uploadBody = new FormData();
      uploadBody.set('file', upload);

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-upload',
          {
            method: 'POST',
            body: uploadBody,
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageUploadStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const imageUrl =
          payload &&
          payload.image &&
          typeof payload.image.url === 'string'
            ? payload.image.url
            : null;

        setStatus(
          badgeTemplateImageUploadStatus,
          imageUrl === null ? 'Template image uploaded.' : 'Template image uploaded: ' + imageUrl,
          false,
        );
        setTimeout(() => {
          window.location.assign(tenantAdminPath + '/rules/templates');
        }, 900);
      } catch {
        setStatus(
          badgeTemplateImageUploadStatus,
          'Unable to upload template image from this browser session.',
          true,
        );
      }
    });
  }

  if (
    badgeTemplateImageGenerationForm instanceof HTMLFormElement &&
    badgeTemplateImageGenerationStatus instanceof HTMLElement
  ) {
    badgeTemplateImageGenerationForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearBadgeTemplateImageGenerationPoll();
      showBadgeTemplateImageGenerationPreview(null);
      setStatus(
        badgeTemplateImageGenerationStatus,
        'Generating badge image draft. This can take up to 60 seconds...',
        false,
      );
      const data = new FormData(badgeTemplateImageGenerationForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const stylePresetRaw = data.get('stylePreset');
      const promptNotesRaw = data.get('promptNotes');
      const accentColorRaw = data.get('accentColor');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';
      const stylePreset = typeof stylePresetRaw === 'string' ? stylePresetRaw.trim() : '';
      const promptNotes = typeof promptNotesRaw === 'string' ? promptNotesRaw.trim() : '';
      const accentColor = typeof accentColorRaw === 'string' ? accentColorRaw.trim() : '';

      if (badgeTemplateId.length === 0 || stylePreset.length === 0) {
        setStatus(badgeTemplateImageGenerationStatus, 'Badge template and style are required.', true);
        return;
      }

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-generations',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              stylePreset,
              ...(promptNotes.length === 0 ? {} : { promptNotes }),
              ...(accentColor.length === 0 ? {} : { accentColor }),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const generationId =
          payload &&
          payload.generation &&
          typeof payload.generation.id === 'string'
            ? payload.generation.id
            : '';

        if (generationId.length === 0) {
          setStatus(badgeTemplateImageGenerationStatus, 'Generation completed without an id.', true);
          return;
        }

        activeBadgeTemplateImageGeneration = {
          badgeTemplateId,
          generationId,
        };
        const generation = payload && payload.generation ? payload.generation : null;

        if (
          generation &&
          generation.status === 'succeeded' &&
          typeof generation.resultImageUri === 'string' &&
          generation.resultImageUri.length > 0
        ) {
          showBadgeTemplateImageGenerationPreview(generation);
          setStatus(badgeTemplateImageGenerationStatus, 'Generated draft ready.', false, 'success');
          return;
        }

        setStatus(
          badgeTemplateImageGenerationStatus,
          'Generation finished, but no draft image was returned.',
          true,
        );
      } catch {
        setStatus(
          badgeTemplateImageGenerationStatus,
          'Unable to generate badge image from this browser session.',
          true,
        );
      }
    });
  }

  if (
    badgeTemplateImageGenerationApplyButton instanceof HTMLButtonElement &&
    badgeTemplateImageGenerationStatus instanceof HTMLElement
  ) {
    badgeTemplateImageGenerationApplyButton.addEventListener('click', async () => {
      if (
        !activeBadgeTemplateImageGeneration ||
        typeof activeBadgeTemplateImageGeneration.badgeTemplateId !== 'string' ||
        typeof activeBadgeTemplateImageGeneration.generationId !== 'string'
      ) {
        setStatus(badgeTemplateImageGenerationStatus, 'No generated draft is selected.', true);
        return;
      }

      badgeTemplateImageGenerationApplyButton.disabled = true;
      setStatus(badgeTemplateImageGenerationStatus, 'Applying generated badge image...', false);

      try {
        const response = await fetch(
          badgeTemplateImageGenerationPath(
            activeBadgeTemplateImageGeneration.badgeTemplateId,
            activeBadgeTemplateImageGeneration.generationId,
          ) + '/apply',
          {
            method: 'POST',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageGenerationStatus, errorDetailFromPayload(payload), true);
          badgeTemplateImageGenerationApplyButton.disabled = false;
          return;
        }

        setStatus(badgeTemplateImageGenerationStatus, 'Generated image applied.', false, 'success');
        setTimeout(() => {
          window.location.assign(tenantAdminPath + '/rules/templates');
        }, 900);
      } catch {
        setStatus(
          badgeTemplateImageGenerationStatus,
          'Unable to apply generated badge image from this browser session.',
          true,
        );
        badgeTemplateImageGenerationApplyButton.disabled = false;
      }
    });
  }

  if (
    badgeTemplateImageRevisionForm instanceof HTMLFormElement &&
    badgeTemplateImageRevisionStatus instanceof HTMLElement
  ) {
    badgeTemplateImageRevisionForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = new FormData(badgeTemplateImageRevisionForm);
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';

      await loadBadgeTemplateImageRevisions(badgeTemplateId);
    });
  }

  document.querySelectorAll('[data-template-image-history-template-id]').forEach((candidate) => {
    if (!(candidate instanceof HTMLAnchorElement)) {
      return;
    }

    candidate.addEventListener('click', async (event) => {
      event.preventDefault();
      const badgeTemplateId = candidate.dataset.templateImageHistoryTemplateId || '';

      if (templateImagePanel instanceof HTMLDetailsElement) {
        templateImagePanel.open = true;
      }

      if (badgeTemplateImageRevisionForm instanceof HTMLFormElement) {
        const templateSelect = badgeTemplateImageRevisionForm.elements.namedItem('badgeTemplateId');

        if (templateSelect instanceof HTMLSelectElement) {
          templateSelect.value = badgeTemplateId;
        }
      }

      if (badgeTemplateImageRevisionStatus instanceof HTMLElement) {
        badgeTemplateImageRevisionStatus.scrollIntoView({ block: 'center' });
      }

      await loadBadgeTemplateImageRevisions(badgeTemplateId);
    });
  });

  if (
    badgeTemplateImageRevisionList instanceof HTMLElement &&
    badgeTemplateImageRevisionStatus instanceof HTMLElement
  ) {
    badgeTemplateImageRevisionList.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLButtonElement)) {
        return;
      }

      const badgeTemplateId = target.dataset.badgeTemplateId || '';
      const revisionId = target.dataset.revisionId || '';

      if (badgeTemplateId.length === 0 || revisionId.length === 0) {
        setStatus(badgeTemplateImageRevisionStatus, 'Invalid image revision action.', true);
        return;
      }

      target.disabled = true;
      setStatus(badgeTemplateImageRevisionStatus, 'Restoring badge image...', false);

      try {
        const response = await fetch(
          badgeTemplateApiPathPrefix +
            '/' +
            encodeURIComponent(badgeTemplateId) +
            '/image-revisions/' +
            encodeURIComponent(revisionId) +
            '/restore',
          {
            method: 'POST',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(badgeTemplateImageRevisionStatus, errorDetailFromPayload(payload), true);
          target.disabled = false;
          return;
        }

        setStatus(badgeTemplateImageRevisionStatus, 'Badge image restored.', false, 'success');
        setTimeout(() => {
          window.location.assign(tenantAdminPath + '/rules/templates');
        }, 900);
      } catch {
        setStatus(
          badgeTemplateImageRevisionStatus,
          'Unable to restore badge image from this browser session.',
          true,
        );
        target.disabled = false;
      }
    });
  }

  if (tenantMemberForm instanceof HTMLFormElement && tenantMemberStatus instanceof HTMLElement) {
    tenantMemberForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(tenantMemberStatus, 'Adding member...', false);

      const data = new FormData(tenantMemberForm);
      const emailRaw = data.get('email');
      const roleRaw = data.get('role');
      const email = typeof emailRaw === 'string' ? emailRaw.trim() : '';
      const role = typeof roleRaw === 'string' ? roleRaw.trim() : '';
      const validRoles = new Set(['owner', 'admin', 'issuer', 'viewer']);

      if (email.length === 0 || role.length === 0) {
        setStatus(tenantMemberStatus, 'Email and tenant role are required.', true);
        return;
      }

      if (!validRoles.has(role)) {
        setStatus(tenantMemberStatus, 'Invalid tenant role.', true);
        return;
      }

      try {
        const response = await fetch(tenantMembersApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            email,
            role,
            sendInvite: data.get('sendInvite') !== null,
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(tenantMemberStatus, 'Member saved.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(tenantMemberStatus, 'Unable to add the member from this browser session.', true);
      }
    });
  }

  if (tenantMemberBody instanceof HTMLElement && tenantMemberListStatus instanceof HTMLElement) {
    tenantMemberBody.addEventListener('change', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLSelectElement)) {
        return;
      }

      const userId = target.dataset.tenantMemberRoleUserId ?? '';
      const currentRole = target.dataset.tenantMemberCurrentRole ?? '';
      const nextRole = target.value.trim();
      const validRoles = new Set(['owner', 'admin', 'issuer', 'viewer']);

      if (userId.length === 0) {
        setStatus(tenantMemberListStatus, 'Member user ID is missing from this role control.', true);
        target.value = currentRole;
        return;
      }

      if (nextRole === currentRole) {
        return;
      }

      if (!validRoles.has(nextRole)) {
        setStatus(tenantMemberListStatus, 'Invalid tenant role.', true);
        target.value = currentRole;
        return;
      }

      setStatus(tenantMemberListStatus, 'Updating member role...', false);
      target.disabled = true;

      try {
        const response = await fetch(
          tenantMembersApiPath + '/' + encodeURIComponent(userId) + '/role',
          {
            method: 'PATCH',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              role: nextRole,
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
          target.value = currentRole;
          target.disabled = false;
          return;
        }

        setStatus(tenantMemberListStatus, 'Member role updated.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          tenantMemberListStatus,
          'Unable to update the member role from this browser session.',
          true,
        );
        target.value = currentRole;
        target.disabled = false;
      }
    });

    tenantMemberBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const inviteButton = target.closest('[data-tenant-member-invite-user-id]');

      if (inviteButton instanceof HTMLElement) {
        const userId = inviteButton.dataset.tenantMemberInviteUserId ?? '';
        const email = inviteButton.dataset.tenantMemberEmail ?? 'this member';

        if (userId.length === 0) {
          setStatus(tenantMemberListStatus, 'Member user ID is missing from invite action.', true);
          return;
        }

        setStatus(tenantMemberListStatus, 'Sending member invite...', false);

        try {
          const response = await fetch(
            tenantMembersApiPath + '/' + encodeURIComponent(userId) + '/invite',
            {
              method: 'POST',
            },
          );
          const payload = await parseJsonBody(response);

          if (!response.ok) {
            setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
            return;
          }

          const deliveryStatus =
            payload &&
            payload.invite &&
            typeof payload.invite.deliveryStatus === 'string'
              ? payload.invite.deliveryStatus
              : 'sent';
          setStatus(
            tenantMemberListStatus,
            'Invite processed for ' + email + ' (' + deliveryStatus + ').',
            false,
            deliveryStatus === 'failed' ? 'warning' : 'success',
          );
        } catch {
          setStatus(
            tenantMemberListStatus,
            'Unable to send the member invite from this browser session.',
            true,
          );
        }

        return;
      }

      const removeButton = target.closest('[data-tenant-member-remove-user-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const userId = removeButton.dataset.tenantMemberRemoveUserId ?? '';
      const email = removeButton.dataset.tenantMemberEmail ?? 'this member';

      if (userId.length === 0) {
        setStatus(tenantMemberListStatus, 'Member user ID is missing from remove action.', true);
        return;
      }

      if (!window.confirm('Remove tenant access for ' + email + '?')) {
        return;
      }

      setStatus(tenantMemberListStatus, 'Removing tenant member...', false);

      try {
        const response = await fetch(
          tenantMembersApiPath + '/' + encodeURIComponent(userId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(tenantMemberListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const removed = payload && typeof payload.removed === 'boolean' ? payload.removed : false;

        if (!removed) {
          setStatus(tenantMemberListStatus, 'No matching tenant membership was found.', true);
          return;
        }

        setStatus(tenantMemberListStatus, 'Tenant member removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          tenantMemberListStatus,
          'Unable to remove the tenant member from this browser session.',
          true,
        );
      }
    });
  }

  if (membershipScopeForm instanceof HTMLFormElement && membershipScopeStatus instanceof HTMLElement) {
    membershipScopeForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(membershipScopeStatus, 'Saving scoped role...', false);
      const data = new FormData(membershipScopeForm);
      const userIdRaw = data.get('userId');
      const orgUnitIdRaw = data.get('orgUnitId');
      const roleRaw = data.get('role');
      const userId = typeof userIdRaw === 'string' ? userIdRaw.trim() : '';
      const orgUnitId = typeof orgUnitIdRaw === 'string' ? orgUnitIdRaw.trim() : '';
      const role = typeof roleRaw === 'string' ? roleRaw.trim() : '';

      if (userId.length === 0 || orgUnitId.length === 0 || role.length === 0) {
        setStatus(
          membershipScopeStatus,
          'Tenant member user ID, org unit, and scoped role are required.',
          true,
        );
        return;
      }

      const validRoles = new Set(['admin', 'issuer', 'viewer']);

      if (!validRoles.has(role)) {
        setStatus(membershipScopeStatus, 'Invalid role. Use admin, issuer, or viewer.', true);
        return;
      }

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(userId) +
            '/org-unit-scopes/' +
            encodeURIComponent(orgUnitId),
          {
            method: 'PUT',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              role,
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(membershipScopeStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(membershipScopeStatus, 'Scoped role saved for ' + userId + '.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          membershipScopeStatus,
          'Unable to save the scoped role from this browser session.',
          true,
        );
      }
    });
  }

  if (membershipScopeBody instanceof HTMLElement && membershipScopeListStatus instanceof HTMLElement) {
    membershipScopeBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const removeButton = target.closest('[data-membership-scope-remove-user-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const userId = removeButton.dataset.membershipScopeRemoveUserId ?? '';
      const orgUnitId = removeButton.dataset.membershipScopeRemoveOrgUnitId ?? '';
      const label = removeButton.dataset.membershipScopeRemoveLabel ?? 'this scoped role';

      if (userId.length === 0 || orgUnitId.length === 0) {
        setStatus(membershipScopeListStatus, 'Scoped role identifiers are missing.', true);
        return;
      }

      if (!window.confirm('Remove scoped role for ' + label + '?')) {
        return;
      }

      setStatus(membershipScopeListStatus, 'Removing scoped role...', false);

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(userId) +
            '/org-unit-scopes/' +
            encodeURIComponent(orgUnitId),
          {
            method: 'DELETE',
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(membershipScopeListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const removed = payload && typeof payload.removed === 'boolean' ? payload.removed : false;

        if (!removed) {
          setStatus(membershipScopeListStatus, 'No matching scoped role was found.', true);
          return;
        }

        setStatus(membershipScopeListStatus, 'Scoped role removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          membershipScopeListStatus,
          'Unable to remove the scoped role from this browser session.',
          true,
        );
      }
    });
  }

  if (delegatedGrantForm instanceof HTMLFormElement && delegatedGrantStatus instanceof HTMLElement) {
    delegatedGrantForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(delegatedGrantStatus, 'Saving delegation...', false);
      const data = new FormData(delegatedGrantForm);
      const delegateUserIdRaw = data.get('delegateUserId');
      const orgUnitIdRaw = data.get('orgUnitId');
      const badgeTemplateIdsRaw = data.get('badgeTemplateIds');
      const reasonRaw = data.get('reason');
      const endsAtRaw = data.get('endsAt');
      const delegateUserId = typeof delegateUserIdRaw === 'string' ? delegateUserIdRaw.trim() : '';
      const orgUnitId = typeof orgUnitIdRaw === 'string' ? orgUnitIdRaw.trim() : '';
      const badgeTemplateIds = toCommaSeparatedList(badgeTemplateIdsRaw);
      const reason = typeof reasonRaw === 'string' ? reasonRaw.trim() : '';
      const endsAtLocal = typeof endsAtRaw === 'string' ? endsAtRaw.trim() : '';
      const allowedActions = data
        .getAll('allowedAction')
        .map((value) => (typeof value === 'string' ? value.trim() : ''))
        .filter((value) => value.length > 0);

      if (delegateUserId.length === 0 || orgUnitId.length === 0) {
        setStatus(delegatedGrantStatus, 'Delegate user ID and org unit are required.', true);
        return;
      }

      if (allowedActions.length === 0) {
        setStatus(delegatedGrantStatus, 'Select at least one allowed action.', true);
        return;
      }

      const validActions = new Set(['issue_badge', 'revoke_badge', 'manage_lifecycle']);
      const invalidAction = allowedActions.find((action) => !validActions.has(action));

      if (invalidAction !== undefined) {
        setStatus(
          delegatedGrantStatus,
          'Invalid delegated action: ' + invalidAction + '.',
          true,
        );
        return;
      }

      if (endsAtLocal.length === 0) {
        setStatus(delegatedGrantStatus, 'Choose when this delegation should end.', true);
        return;
      }

      const parsedEndsAtMs = Date.parse(endsAtLocal);

      if (!Number.isFinite(parsedEndsAtMs)) {
        setStatus(delegatedGrantStatus, 'Ends at must be a valid date/time.', true);
        return;
      }

      const endsAtIso = new Date(parsedEndsAtMs).toISOString();

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(delegateUserId) +
            '/issuing-authority-grants',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              orgUnitId,
              allowedActions,
              ...(badgeTemplateIds.length > 0 ? { badgeTemplateIds } : {}),
              endsAt: endsAtIso,
              ...(reason.length > 0 ? { reason } : {}),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(delegatedGrantStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const grantId =
          payload && payload.grant && typeof payload.grant.id === 'string'
            ? payload.grant.id
            : '';
        setStatus(
          delegatedGrantStatus,
          'Delegation saved.' + (grantId.length > 0 ? ' Grant ID: ' + grantId + '.' : ''),
          false,
          'success',
        );
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          delegatedGrantStatus,
          'Unable to save the delegation from this browser session.',
          true,
        );
      }
    });
  }

  if (delegatedGrantBody instanceof HTMLElement && delegatedGrantListStatus instanceof HTMLElement) {
    delegatedGrantBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const removeButton = target.closest('[data-delegated-grant-remove-id]');

      if (!(removeButton instanceof HTMLElement)) {
        return;
      }

      const delegateUserId = removeButton.dataset.delegatedGrantRemoveUserId ?? '';
      const grantId = removeButton.dataset.delegatedGrantRemoveId ?? '';
      const label = removeButton.dataset.delegatedGrantRemoveLabel ?? 'this delegation';

      if (delegateUserId.length === 0 || grantId.length === 0) {
        setStatus(delegatedGrantListStatus, 'Delegation identifiers are missing.', true);
        return;
      }

      if (!window.confirm('Remove delegation for ' + label + '?')) {
        return;
      }

      setStatus(delegatedGrantListStatus, 'Removing delegation...', false);

      try {
        const response = await fetch(
          tenantUsersApiPathPrefix +
            '/' +
            encodeURIComponent(delegateUserId) +
            '/issuing-authority-grants/' +
            encodeURIComponent(grantId) +
            '/revoke',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({}),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(delegatedGrantListStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(delegatedGrantListStatus, 'Delegation removed.', false, 'success');
        setTimeout(() => {
          reloadCurrentPage();
        }, 700);
      } catch {
        setStatus(
          delegatedGrantListStatus,
          'Unable to remove the delegation from this browser session.',
          true,
        );
      }
    });
  }

  if (
    assertionLifecycleViewForm instanceof HTMLFormElement &&
    assertionLifecycleViewStatus instanceof HTMLElement
  ) {
    assertionLifecycleViewForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = new FormData(assertionLifecycleViewForm);
      const assertionIdRaw = data.get('assertionId');
      await loadAssertionLifecycle(assertionIdRaw, assertionLifecycleViewStatus);
    });
  }

  if (
    assertionLifecycleTransitionForm instanceof HTMLFormElement &&
    assertionLifecycleTransitionStatus instanceof HTMLElement
  ) {
    assertionLifecycleTransitionForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(assertionLifecycleTransitionStatus, 'Applying lifecycle transition...', false);
      const data = new FormData(assertionLifecycleTransitionForm);
      const assertionIdRaw = data.get('assertionId');
      const toStateRaw = data.get('toState');
      const reasonCodeRaw = data.get('reasonCode');
      const reasonRaw = data.get('reason');
      const assertionId = typeof assertionIdRaw === 'string' ? assertionIdRaw.trim() : '';
      const toState = typeof toStateRaw === 'string' ? toStateRaw.trim() : '';
      const reasonCode = typeof reasonCodeRaw === 'string' ? reasonCodeRaw.trim() : '';
      const reason = typeof reasonRaw === 'string' ? reasonRaw.trim() : '';

      if (assertionId.length === 0 || toState.length === 0 || reasonCode.length === 0) {
        setStatus(
          assertionLifecycleTransitionStatus,
          'Assertion ID, target state, and reason code are required.',
          true,
        );
        return;
      }

      try {
        const response = await fetch(
          assertionsApiPathPrefix +
            '/' +
            encodeURIComponent(assertionId) +
            '/lifecycle/transition',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              toState,
              reasonCode,
              ...(reason.length > 0 ? { reason } : {}),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(assertionLifecycleTransitionStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const status = payload && typeof payload.status === 'string' ? payload.status : 'updated';
        const currentState =
          payload && typeof payload.currentState === 'string' ? payload.currentState : toState;
        setStatus(
          assertionLifecycleTransitionStatus,
          'Lifecycle transition result: status=' + status + ', currentState=' + currentState + '.',
          false,
        );
      } catch {
        setStatus(
          assertionLifecycleTransitionStatus,
          'Unable to apply lifecycle transition from this browser session.',
          true,
        );
      }
    });
  }

  if (
    issuedBadgesFilterForm instanceof HTMLFormElement &&
    issuedBadgesStatus instanceof HTMLElement &&
    issuedBadgesBody instanceof HTMLElement &&
    issuedBadgesActionStatus instanceof HTMLElement
  ) {
    const loadIssuedBadges = async () => {
      setStatus(issuedBadgesStatus, 'Loading issued badges...', false);
      setIssuedBadgesEmptyState('Loading assertions...');
      const data = new FormData(issuedBadgesFilterForm);
      const recipientQueryRaw = data.get('recipientQuery');
      const badgeTemplateIdRaw = data.get('badgeTemplateId');
      const stateRaw = data.get('state');
      const limitRaw = data.get('limit');
      const recipientQuery =
        typeof recipientQueryRaw === 'string' ? recipientQueryRaw.trim() : '';
      const badgeTemplateId =
        typeof badgeTemplateIdRaw === 'string' ? badgeTemplateIdRaw.trim() : '';
      const state = typeof stateRaw === 'string' ? stateRaw.trim() : '';
      const limit = parseIssuedBadgesLimit(limitRaw);
      const query = new URLSearchParams();
      query.set('limit', String(limit));

      if (recipientQuery.length > 0) {
        query.set('recipientQuery', recipientQuery);
      }

      if (badgeTemplateId.length > 0) {
        query.set('badgeTemplateId', badgeTemplateId);
      }

      if (state.length > 0) {
        query.set('state', state);
      }

      try {
        const response = await fetch(issuedBadgeRowsPath + '?' + query.toString(), {
          headers: {
            accept: 'text/html',
          },
        });

        if (!response.ok) {
          const payload = await parseJsonBody(response);
          setStatus(issuedBadgesStatus, errorDetailFromPayload(payload), true);
          setIssuedBadgesEmptyState('Unable to load assertions.');
          return;
        }

        const html = await response.text();
        const countRaw = response.headers.get('x-credtrail-assertion-count');
        const count = countRaw === null ? 0 : Number.parseInt(countRaw, 10);
        const loadedCount = Number.isFinite(count) ? count : 0;
        issuedBadgesBody.innerHTML = html;
        setStatus(
          issuedBadgesStatus,
          'Loaded ' + String(loadedCount) + ' assertion' + (loadedCount === 1 ? '' : 's') + '.',
          false,
        );
      } catch {
        setStatus(issuedBadgesStatus, 'Unable to load assertions from this browser session.', true);
        setIssuedBadgesEmptyState('Unable to load assertions.');
      }
    };

    refreshIssuedBadges = loadIssuedBadges;

    const closeIssuedActionMenus = (exceptMenu) => {
      const openMenus = issuedBadgesBody.querySelectorAll('details.ct-admin__action-menu[open]');

      openMenus.forEach((menu) => {
        if (!(menu instanceof HTMLDetailsElement) || menu === exceptMenu) {
          return;
        }

        menu.open = false;
      });
    };

    const revokeAssertion = async (assertionId) => {
      const reasonPrompt = window.prompt(
        'Optional revocation reason for ' + assertionId + ':',
        'Institution admin revocation',
      );

      if (reasonPrompt === null) {
        return;
      }

      setStatus(issuedBadgesActionStatus, 'Revoking assertion ' + assertionId + '...', false);

      try {
        const response = await fetch(
          assertionsApiPathPrefix +
            '/' +
            encodeURIComponent(assertionId) +
            '/lifecycle/transition',
          {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
            },
            body: JSON.stringify({
              toState: 'revoked',
              reasonCode: 'issuer_requested',
              ...(reasonPrompt.trim().length > 0 ? { reason: reasonPrompt.trim() } : {}),
            }),
          },
        );
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(issuedBadgesActionStatus, errorDetailFromPayload(payload), true);
          return;
        }

        setStatus(issuedBadgesActionStatus, 'Assertion revoked: ' + assertionId + '.', false);
        await loadAssertionLifecycle(assertionId, assertionLifecycleViewStatus);
        await loadIssuedBadges();
      } catch {
        setStatus(
          issuedBadgesActionStatus,
          'Unable to revoke assertion from this browser session.',
          true,
        );
      }
    };

    issuedBadgesFilterForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      await loadIssuedBadges();
    });

    document.addEventListener('click', (event) => {
      if (!(event.target instanceof Node)) {
        return;
      }

      if (issuedBadgesBody.contains(event.target)) {
        return;
      }

      closeIssuedActionMenus();
    });

    issuedBadgesBody.addEventListener('click', async (event) => {
      const target = event.target;

      if (!(target instanceof HTMLElement)) {
        return;
      }

      const menuTrigger = target.closest('summary.ct-admin__action-menu-trigger');

      if (menuTrigger instanceof HTMLElement) {
        const menu = menuTrigger.parentElement;

        if (menu instanceof HTMLDetailsElement) {
          window.setTimeout(() => {
            closeIssuedActionMenus(menu.open ? menu : undefined);
          }, 0);
        }

        return;
      }

      const menuLink = target.closest('a.ct-admin__action-menu-item');

      if (menuLink instanceof HTMLAnchorElement) {
        const menu = menuLink.closest('details.ct-admin__action-menu');

        if (menu instanceof HTMLDetailsElement) {
          menu.open = false;
        }

        return;
      }

      const actionButton = target.closest('button[data-issued-action]');

      if (!(actionButton instanceof HTMLButtonElement)) {
        return;
      }

      const action = actionButton.dataset.issuedAction;
      const assertionId = actionButton.dataset.assertionId;

      if (typeof assertionId !== 'string' || assertionId.trim().length === 0) {
        setStatus(issuedBadgesActionStatus, 'Missing assertion ID for selected action.', true);
        return;
      }

      const parentMenu = actionButton.closest('details.ct-admin__action-menu');

      if (parentMenu instanceof HTMLDetailsElement) {
        parentMenu.open = false;
      }

      if (action === 'audit') {
        setStatus(issuedBadgesActionStatus, 'Loading lifecycle audit for ' + assertionId + '...', false);
        const lifecyclePayload = await loadAssertionLifecycle(
          assertionId,
          assertionLifecycleViewStatus,
        );

        if (lifecyclePayload === null) {
          setStatus(issuedBadgesActionStatus, 'Unable to load lifecycle audit.', true);
          return;
        }

        setStatus(issuedBadgesActionStatus, 'Lifecycle audit loaded for ' + assertionId + '.', false);
        const lifecyclePanel = document.getElementById('lifecycle-panel');

        if (lifecyclePanel instanceof HTMLElement) {
          lifecyclePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        return;
      }

      if (action === 'revoke') {
        if (
          !window.confirm(
            'Revoke assertion "' + assertionId + '"? This changes credential lifecycle state.',
          )
        ) {
          return;
        }

        await revokeAssertion(assertionId);
      }
    });

    void loadIssuedBadges();
  }

  if (ruleGovernanceForm instanceof HTMLFormElement && ruleGovernanceStatus instanceof HTMLElement) {
    ruleGovernanceForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(ruleGovernanceStatus, 'Loading rule governance context...', false);
      setCodeOutput(ruleGovernanceOutput, '');
      const data = new FormData(ruleGovernanceForm);
      const ruleIdRaw = data.get('ruleId');
      const auditLimitRaw = data.get('auditLimit');
      const ruleId = typeof ruleIdRaw === 'string' ? ruleIdRaw.trim() : '';
      const parsedAuditLimit = Number(
        typeof auditLimitRaw === 'string' ? auditLimitRaw.trim() : '',
      );
      const auditLimit =
        Number.isFinite(parsedAuditLimit) && parsedAuditLimit >= 1 && parsedAuditLimit <= 100
          ? Math.trunc(parsedAuditLimit)
          : 20;
      const ruleSelect = ruleGovernanceForm.elements.namedItem('ruleId');
      const selectedOption =
        ruleSelect instanceof HTMLSelectElement ? ruleSelect.selectedOptions.item(0) : null;
      const versionId = selectedOption?.dataset.versionId?.trim() ?? '';

      if (ruleId.length === 0) {
        setStatus(ruleGovernanceStatus, 'Rule selection is required.', true);
        return;
      }

      if (versionId.length === 0) {
        setStatus(
          ruleGovernanceStatus,
          'Selected rule has no version context to inspect.',
          true,
        );
        return;
      }

      const approvalHistoryPath =
        badgeRuleApiPath +
        '/' +
        encodeURIComponent(ruleId) +
        '/versions/' +
        encodeURIComponent(versionId) +
        '/approval-history';
      const auditLogPath =
        badgeRuleApiPath +
        '/' +
        encodeURIComponent(ruleId) +
        '/audit-log?limit=' +
        encodeURIComponent(String(auditLimit));

      try {
        const [approvalResponse, auditResponse] = await Promise.all([
          fetch(approvalHistoryPath),
          fetch(auditLogPath),
        ]);
        const [approvalPayload, auditPayload] = await Promise.all([
          parseJsonBody(approvalResponse),
          parseJsonBody(auditResponse),
        ]);

        if (!approvalResponse.ok) {
          setStatus(ruleGovernanceStatus, errorDetailFromPayload(approvalPayload), true);
          return;
        }

        if (!auditResponse.ok) {
          setStatus(ruleGovernanceStatus, errorDetailFromPayload(auditPayload), true);
          return;
        }

        const currentStep =
          approvalPayload &&
          approvalPayload.approval &&
          approvalPayload.approval.currentStep &&
          typeof approvalPayload.approval.currentStep.stepNumber === 'number'
            ? approvalPayload.approval.currentStep.stepNumber
            : null;
        const logCount = auditPayload && Array.isArray(auditPayload.logs) ? auditPayload.logs.length : 0;

        setStatus(
          ruleGovernanceStatus,
          'Governance context loaded: current approval step=' +
            (currentStep === null ? 'none' : String(currentStep)) +
            ', audit events=' +
            String(logCount) +
            '.',
          false,
        );
        setCodeOutput(
          ruleGovernanceOutput,
          JSON.stringify(
            {
              ruleId,
              versionId,
              approval: approvalPayload?.approval ?? null,
              auditLogs: auditPayload?.logs ?? [],
            },
            null,
            2,
          ),
        );
      } catch {
        setStatus(
          ruleGovernanceStatus,
          'Unable to load rule governance context from this browser session.',
          true,
        );
      }
    });
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

    const defaultTemplateDefinitions = {
      blank: {
        conditions: {
          all: [
            {
              type: 'course_completion',
              courseId: 'CS101',
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
              courseId: 'CS101',
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
              courseId: 'CS101',
              requireCompleted: true,
            },
            {
              type: 'grade_threshold',
              courseId: 'CS101',
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
              courseIds: ['CS101', 'CS102', 'CS103'],
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
              courseId: 'CS101',
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
              surveyId: 'CS101_EXIT_SURVEY',
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
              courseId: 'CS101',
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
              courseId: 'CS201',
              requireCompleted: true,
            },
          ],
        },
      },
    };

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

    const ruleBuilderStepPanels = Array.from(
      ruleCreateForm.querySelectorAll('[data-rule-step]'),
    ).filter((candidate) => candidate instanceof HTMLElement);
    const ruleBuilderStepOrder = ruleBuilderStepPanels
      .map((candidate) => candidate.dataset.ruleStep ?? '')
      .filter((stepName) => stepName.length > 0);
    const ruleBuilderStepLabels = {
      metadata: 'Awarding pattern',
      conditions: 'Requirements',
      test: 'Test & submit',
    };
    let activeRuleBuilderStepIndex = 0;

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

      if (ruleBuilderStepPrevButton instanceof HTMLButtonElement) {
        ruleBuilderStepPrevButton.disabled = nextIndex === 0;
      }

      if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
        ruleBuilderStepNextButton.disabled = nextIndex >= ruleBuilderStepOrder.length - 1;
      }

      if (ruleBuilderSubmitButton instanceof HTMLButtonElement) {
        ruleBuilderSubmitButton.disabled = nextIndex < ruleBuilderStepOrder.length - 1;
      }
      if (ruleBuilderStepProgress instanceof HTMLElement) {
        ruleBuilderStepProgress.textContent =
          'Step ' +
          String(nextIndex + 1) +
          ' of ' +
          String(ruleBuilderStepOrder.length) +
          ' · ' +
          activeStepLabel;
      }
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

    const updateConditionHelpText = (card, conditionType) => {
      const helpElement = card.querySelector('.ct-admin__condition-help');

      if (!(helpElement instanceof HTMLElement)) {
        return;
      }

      const helpText = conditionTypeHelpText[conditionType] ?? 'Configure condition inputs.';
      helpElement.textContent = helpText;
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
      updateConditionHelpText(card, conditionType);

      if (conditionType === 'course_completion') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="CS101" /></label>' +
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
        return;
      }

      if (conditionType === 'grade_threshold') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="CS101" /></label>' +
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
        return;
      }

      if (conditionType === 'program_completion') {
        fieldsContainer.innerHTML =
          '<label>Course IDs (comma separated)<input type="text" data-field="courseIds" placeholder="CS101,CS102,CS103" /></label>' +
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
        return;
      }

      if (conditionType === 'assignment_submission') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="CS101" /></label>' +
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
        return;
      }

      if (conditionType === 'survey_completion') {
        fieldsContainer.innerHTML =
          '<label>Survey ID<input type="text" data-field="surveyId" placeholder="CS101_EXIT_SURVEY" /></label>' +
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
        return;
      }

      if (conditionType === 'time_window') {
        fieldsContainer.innerHTML =
          '<label>Not before (optional)<input type="datetime-local" data-field="notBefore" /></label>' +
          '<label>Not after (optional)<input type="datetime-local" data-field="notAfter" /></label>';

        setFieldOnCard(card, 'notBefore', toDateTimeLocalInput(seed.notBefore));
        setFieldOnCard(card, 'notAfter', toDateTimeLocalInput(seed.notAfter));
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
      const courseId = getTextFieldValue('testCourseId') || 'CS101';
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

    const syncRuleBuilderStepCompletion = (definitionReady) => {
      const metadataReady =
        getTextFieldValue('name').length > 0 &&
        getTextFieldValue('badgeTemplateId').length > 0 &&
        getTextFieldValue('lmsProviderKind').length > 0;
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

      const completionByStep = {
        metadata: metadataReady,
        conditions: definitionReady,
        test: testReady && reviewReady,
      };

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const targetStep = candidate.dataset.ruleStepTarget ?? '';
        const isDone = completionByStep[targetStep] === true;
        candidate.classList.toggle('is-done', isDone);
      });

      const completedCount = Object.values(completionByStep).filter((value) => value).length;
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
      syncRuleBuilderStepCompletion(definitionTone === 'success');
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
          courseId: 'CS101',
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
        syncRuleBuilderSummary('Blank requirements started.');
        return;
      }

      const selectedTemplate = defaultTemplateDefinitions[presetKey] ?? defaultTemplateDefinitions.course_and_grade;
      ruleBuilderDefinitionJson.value = JSON.stringify(selectedTemplate, null, 2);
      applyDefinitionToBuilder(selectedTemplate, 'Template');
    };

    const applyTestFactPreset = () => {
      const presetKey =
        ruleBuilderTestPresetSelect instanceof HTMLSelectElement
          ? ruleBuilderTestPresetSelect.value.trim()
          : 'canvas_course_grade';
      const learnerId = getTextFieldValue('testLearnerId') || 'canvas:12345';
      const recipientIdentity = getTextFieldValue('testRecipientIdentity') || 'learner@example.edu';

      setRuleCreateFieldValue('testLearnerId', learnerId);
      setRuleCreateFieldValue('testRecipientIdentity', recipientIdentity);

      if (presetKey === 'program_completion') {
        setRuleCreateFieldValue('testCourseId', 'CS101');
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              completions: [
                {
                  courseId: 'CS101',
                  learnerId,
                  completed: true,
                  completionPercent: 100,
                },
                {
                  courseId: 'CS102',
                  learnerId,
                  completed: true,
                  completionPercent: 100,
                },
                {
                  courseId: 'CS103',
                  learnerId,
                  completed: true,
                  completionPercent: 100,
                },
              ],
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'assignment_submission') {
        setRuleCreateFieldValue('testCourseId', 'CS101');
        setRuleCreateFieldValue('testFinalScore', '88');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              submissions: [
                {
                  courseId: 'CS101',
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
      } else if (presetKey === 'prerequisite_badge') {
        setRuleCreateFieldValue('testCourseId', 'CS201');
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
        setRuleCreateFieldValue('testCourseId', 'CS101');
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              surveyCompletions: [
                {
                  surveyId: 'CS101_EXIT_SURVEY',
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
        setRuleCreateFieldValue('testCourseId', 'CS101');
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
        setRuleCreateFieldValue('testCourseId', 'CS101');
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
            setBuilderStepState(targetIndex);
          }
        });
      });
    }

    if (ruleBuilderStepPrevButton instanceof HTMLButtonElement) {
      ruleBuilderStepPrevButton.addEventListener('click', () => {
        setBuilderStepState(activeRuleBuilderStepIndex - 1);
      });
    }

    if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
      ruleBuilderStepNextButton.addEventListener('click', () => {
        setBuilderStepState(activeRuleBuilderStepIndex + 1);
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
          courseId: 'CS101',
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
          courseId: 'CS101',
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
          setRuleCreateFieldValue('testCourseId', typeof draft.testCourseId === 'string' ? draft.testCourseId : 'CS101');
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
            setRuleCreateFieldValue('name', rule.name + ' copy');
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

    if (ruleBuilderTestButton instanceof HTMLButtonElement) {
      ruleBuilderTestButton.addEventListener('click', async () => {
        setStatus(ruleCreateStatus, 'Evaluating rule in test mode...', false);
        setCodeOutput(ruleBuilderTestOutput, '');
        resetConditionEvaluationResults();
        ruleBuilderLastTestSummary = 'Running...';
        syncRuleBuilderSummary('Evaluating rule in test mode...');

        let definition;

        try {
          definition = parseDefinitionJson();
        } catch (error) {
          setStatus(
            ruleCreateStatus,
            error instanceof Error ? error.message : 'Rule definition is invalid.',
            true,
          );
          ruleBuilderLastTestSummary = 'Definition invalid';
          syncRuleBuilderSummary(error instanceof Error ? error.message : 'Rule definition is invalid.');
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
          setStatus(ruleCreateStatus, 'Test mode requires learner ID and recipient email.', true);
          ruleBuilderLastTestSummary = 'Missing test identifiers';
          syncRuleBuilderSummary('Test mode requires learner ID and recipient email.');
          return;
        }

        let facts = undefined;

        if (testFactsJson.length > 0) {
          try {
            facts = JSON.parse(testFactsJson);
          } catch {
            setStatus(ruleCreateStatus, 'Advanced facts JSON is invalid.', true);
            ruleBuilderLastTestSummary = 'Facts JSON invalid';
            syncRuleBuilderSummary('Advanced facts JSON is invalid.');
            return;
          }
        } else if (sampleCourseId.length > 0) {
          const sampleFinalScore = Number(sampleFinalScoreText);

          if (!Number.isFinite(sampleFinalScore) || sampleFinalScore < 0 || sampleFinalScore > 100) {
            setStatus(
              ruleCreateStatus,
              'Sample final score must be a number between 0 and 100.',
              true,
            );
            ruleBuilderLastTestSummary = 'Sample score invalid';
            syncRuleBuilderSummary('Sample final score must be a number between 0 and 100.');
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
            setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
            ruleBuilderLastTestSummary = 'Failed';
            syncRuleBuilderSummary(errorDetailFromPayload(payload));
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
          setStatus(
            ruleCreateStatus,
            'Test evaluation complete. outcome=' +
              outcomeLabel +
              '.' +
              (missingDataCount > 0
                ? ' Missing data=' + String(missingDataCount) + '.'
                : '') +
              conditionSummaryText,
            false,
            outcome === 'matched' ? 'success' : 'warning',
          );
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
              (missingDataCount > 0
                ? ' Missing data=' + String(missingDataCount) + '.'
                : '') +
              conditionSummaryText,
          );
          setCodeOutput(ruleBuilderTestOutput, JSON.stringify(payload, null, 2));
        } catch {
          setStatus(ruleCreateStatus, 'Unable to run rule test from this browser session.', true);
          ruleBuilderLastTestSummary = 'Failed';
          syncRuleBuilderSummary('Unable to run rule test from this browser session.');
        }
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

    setBuilderStepState(0);
    applyTemplatePreset();
    void loadRuleValueLists(null, {
      quietSuccess: true,
    }).then(() => {
      refreshConditionCardValueListOptions();
    });
    syncRuleBuilderSummary();
  }

  if (ruleEvaluateForm instanceof HTMLFormElement && ruleEvaluateStatus instanceof HTMLElement) {
    ruleEvaluateForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      setStatus(ruleEvaluateStatus, 'Evaluating rule...', false);
      const data = new FormData(ruleEvaluateForm);
      const ruleIdRaw = data.get('ruleId');
      const learnerIdRaw = data.get('learnerId');
      const recipientIdentityRaw = data.get('recipientIdentity');
      const courseIdRaw = data.get('courseId');
      const finalScoreRaw = data.get('finalScore');
      const completed = data.get('completed') !== null;
      const dryRun = data.get('dryRun') !== null;
      const ruleId = typeof ruleIdRaw === 'string' ? ruleIdRaw.trim() : '';
      const learnerId = typeof learnerIdRaw === 'string' ? learnerIdRaw.trim() : '';
      const recipientIdentity =
        typeof recipientIdentityRaw === 'string'
          ? recipientIdentityRaw.trim().toLowerCase()
          : '';
      const courseId = typeof courseIdRaw === 'string' ? courseIdRaw.trim() : '';
      const finalScoreText = typeof finalScoreRaw === 'string' ? finalScoreRaw.trim() : '';
      const finalScore = Number(finalScoreText);

      if (
        ruleId.length === 0 ||
        learnerId.length === 0 ||
        recipientIdentity.length === 0 ||
        courseId.length === 0
      ) {
        setStatus(
          ruleEvaluateStatus,
          'Rule, learner ID, recipient email, and course ID are required.',
          true,
        );
        return;
      }

      if (!Number.isFinite(finalScore) || finalScore < 0 || finalScore > 100) {
        setStatus(ruleEvaluateStatus, 'Final score must be a number between 0 and 100.', true);
        return;
      }

      const evaluatePath = badgeRuleApiPath + '/' + encodeURIComponent(ruleId) + '/evaluate';
      let selectedVersionId = '';
      const ruleSelect = ruleEvaluateForm.elements.namedItem('ruleId');

      if (ruleSelect instanceof HTMLSelectElement) {
        const selectedOption = ruleSelect.selectedOptions.item(0);
        selectedVersionId = selectedOption?.dataset.versionId?.trim() ?? '';
      }

      try {
        const response = await fetch(evaluatePath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            learnerId,
            recipientIdentity,
            recipientIdentityType: 'email',
            dryRun,
            ...(selectedVersionId.length > 0 ? { versionId: selectedVersionId } : {}),
            facts: {
              grades: [
                {
                  courseId,
                  learnerId,
                  finalScore,
                },
              ],
              completions: [
                {
                  courseId,
                  learnerId,
                  completed,
                  completionPercent: completed ? 100 : 0,
                },
              ],
            },
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(ruleEvaluateStatus, errorDetailFromPayload(payload), true);
          return;
        }

        const matched =
          Boolean(payload && payload.evaluation && payload.evaluation.matched === true) ===
          true;
        const issuanceStatus =
          payload && payload.issuance && typeof payload.issuance.status === 'string'
            ? payload.issuance.status
            : dryRun
              ? 'dry_run'
              : 'not_issued';
        const assertionId =
          payload && payload.issuance && typeof payload.issuance.assertionId === 'string'
            ? payload.issuance.assertionId
            : null;
        const suffix =
          assertionId === null
            ? ''
            : ' Assertion: ' + assertionId + '.';
        setStatus(
          ruleEvaluateStatus,
          'Evaluation complete. matched=' +
            String(matched) +
            ', issuance=' +
            issuanceStatus +
            '.' +
            suffix,
          false,
        );
      } catch {
        setStatus(ruleEvaluateStatus, 'Unable to evaluate rule from this browser session.', true);
      }
    });
  }

  if (ruleActionStatus instanceof HTMLElement) {
    const postRuleAction = async (candidate, actionPath, body, actionLabel) => {
      if (!(candidate instanceof HTMLButtonElement)) {
        return;
      }

      if (typeof actionPath !== 'string' || actionPath.length === 0) {
        setStatus(ruleActionStatus, 'Missing rule action path.', true);
        return;
      }

      candidate.disabled = true;
      setStatus(ruleActionStatus, actionLabel + '...', false);

      try {
        const response = await fetch(actionPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify(body),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(ruleActionStatus, errorDetailFromPayload(payload), true);
          candidate.disabled = false;
          return;
        }

        setStatus(ruleActionStatus, actionLabel + ' complete.', false);
        setTimeout(() => {
          window.location.assign(tenantAdminPath);
        }, 700);
      } catch {
        setStatus(ruleActionStatus, 'Unable to perform rule action.', true);
        candidate.disabled = false;
      }
    };

    document.querySelectorAll('button[data-rule-submit-path]').forEach((candidate) => {
      if (!(candidate instanceof HTMLButtonElement)) {
        return;
      }

      candidate.addEventListener('click', async () => {
        await postRuleAction(
          candidate,
          candidate.dataset.ruleSubmitPath,
          {},
          'Submitting rule for approval',
        );
      });
    });

    document.querySelectorAll('button[data-rule-decision-path]').forEach((candidate) => {
      if (!(candidate instanceof HTMLButtonElement)) {
        return;
      }

      candidate.addEventListener('click', async () => {
        const decision = candidate.dataset.ruleDecision;
        const label = candidate.dataset.ruleLabel ?? 'rule';

        if (decision !== 'approved' && decision !== 'rejected') {
          setStatus(ruleActionStatus, 'Invalid decision for selected rule action.', true);
          return;
        }

        const confirmed = window.confirm(
          (decision === 'approved' ? 'Approve' : 'Reject') +
            ' latest version for "' +
            label +
            '"?',
        );

        if (!confirmed) {
          return;
        }

        await postRuleAction(
          candidate,
          candidate.dataset.ruleDecisionPath,
          { decision },
          (decision === 'approved' ? 'Approving' : 'Rejecting') + ' rule version',
        );
      });
    });

    document.querySelectorAll('button[data-rule-activate-path]').forEach((candidate) => {
      if (!(candidate instanceof HTMLButtonElement)) {
        return;
      }

      candidate.addEventListener('click', async () => {
        const label = candidate.dataset.ruleLabel ?? 'rule';
        const confirmed = window.confirm('Activate latest approved version for "' + label + '"?');

        if (!confirmed) {
          return;
        }

        await postRuleAction(
          candidate,
          candidate.dataset.ruleActivatePath,
          {},
          'Activating rule version',
        );
      });
    });
  }

  if (apiKeyRevokeStatus instanceof HTMLElement) {
    document
      .querySelectorAll('button[data-revoke-api-key-path]')
      .forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        candidate.addEventListener('click', async () => {
          const revokePath = candidate.dataset.revokeApiKeyPath;
          const label = candidate.dataset.apiKeyLabel ?? 'API key';

          if (typeof revokePath !== 'string' || revokePath.length === 0) {
            setStatus(apiKeyRevokeStatus, 'Missing revoke path for selected key.', true);
            return;
          }

          if (!window.confirm('Revoke key "' + label + '"? This action cannot be undone.')) {
            return;
          }

          candidate.disabled = true;
          setStatus(apiKeyRevokeStatus, 'Revoking API key...', false);

          try {
            const response = await fetch(revokePath, {
              method: 'POST',
              headers: {
                'content-type': 'application/json',
              },
              body: JSON.stringify({}),
            });
            const payload = await parseJsonBody(response);

            if (!response.ok) {
              setStatus(apiKeyRevokeStatus, errorDetailFromPayload(payload), true);
              candidate.disabled = false;
              return;
            }

            setStatus(apiKeyRevokeStatus, 'API key revoked.', false);
            setTimeout(() => {
              window.location.assign(tenantAdminPath);
            }, 700);
          } catch {
            setStatus(
              apiKeyRevokeStatus,
              'Unable to revoke API key from this browser session.',
              true,
            );
            candidate.disabled = false;
          }
        });
      });
  }

  if (reportingFiltersForm instanceof HTMLFormElement) {
    reportingFiltersForm.addEventListener('submit', () => {
      reportingFiltersForm.dataset.reportingSubmitState = 'pending';
      reportingFiltersForm.setAttribute('aria-busy', 'true');

      if (reportingFiltersStatus instanceof HTMLElement) {
        reportingFiltersStatus.textContent = 'Refreshing this page with the selected reporting slice...';
      }

      Array.from(reportingFiltersForm.querySelectorAll('button[type="submit"]')).forEach((candidate) => {
        if (candidate instanceof HTMLButtonElement) {
          candidate.disabled = true;
        }
      });
    });
  }

  const reportingBarGroups = Array.from(document.querySelectorAll('[data-reporting-bar-group]')).filter(
    (candidate) => candidate instanceof HTMLElement,
  );

  for (const group of reportingBarGroups) {
    const barValues = Array.from(group.querySelectorAll('[data-reporting-bar-value]')).filter(
      (candidate) => candidate instanceof HTMLElement,
    );

    if (barValues.length === 0) {
      continue;
    }

    const numericValues = barValues
      .map((candidate) => Number(candidate.getAttribute('data-reporting-bar-value') ?? '0'))
      .filter((value) => Number.isFinite(value) && value >= 0);
    const maxValue =
      numericValues.length === 0 ? 0 : numericValues.reduce((max, value) => Math.max(max, value), 0);

    for (const barValue of barValues) {
      const numericValue = Number(barValue.getAttribute('data-reporting-bar-value') ?? '0');
      const ratio = maxValue > 0 && Number.isFinite(numericValue) ? numericValue / maxValue : 0;

      barValue.style.setProperty('--ct-reporting-bar-ratio', ratio.toFixed(4));
    }
  }

  const reportingFocusSections = Array.from(
    document.querySelectorAll('[data-reporting-focus-section]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusLinks = Array.from(
    document.querySelectorAll('[data-reporting-focus-link]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusSectionsById = new Map(reportingFocusSections.map((section) => [section.id, section]));
  const syncReportingFocusTarget = () => {
    const targetId = window.location.hash.length > 1 ? window.location.hash.slice(1) : '';
    const targetSection = targetId.length > 0 ? reportingFocusSectionsById.get(targetId) : undefined;
    const activeRootTargetId = targetSection?.dataset.reportingFocusRoot ?? '';

    for (const section of reportingFocusSections) {
      const isActive = targetId.length > 0 && section.id === targetId;
      section.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        section.focus({ preventScroll: true });
      }
    }

    for (const link of reportingFocusLinks) {
      const focusTarget = link.dataset.reportingFocusTarget ?? '';
      const isRootLink = link.hasAttribute('data-reporting-root-link');
      const isActive =
        (targetId.length > 0 && focusTarget === targetId) ||
        (isRootLink && activeRootTargetId.length > 0 && focusTarget === activeRootTargetId);

      link.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        link.setAttribute('aria-current', isRootLink ? 'location' : 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    }
  };

  if (reportingFocusSections.length > 0 || reportingFocusLinks.length > 0) {
    syncReportingFocusTarget();
    window.addEventListener('hashchange', syncReportingFocusTarget);
  }

  /* ── Mobile sidebar toggle ── */
  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const sidebar = document.querySelector('.ct-admin-sidebar');

  if (sidebarToggle instanceof HTMLElement && sidebar instanceof HTMLElement) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('ct-admin-sidebar--open');
    });

    document.addEventListener('click', (event) => {
      if (
        sidebar.classList.contains('ct-admin-sidebar--open') &&
        !sidebar.contains(event.target) &&
        event.target !== sidebarToggle
      ) {
        sidebar.classList.remove('ct-admin-sidebar--open');
      }
    });
  }
})();

`;
