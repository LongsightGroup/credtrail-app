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
  const badgeRuleApiPath =
    parsedContext && typeof parsedContext.badgeRuleApiPath === 'string'
      ? parsedContext.badgeRuleApiPath
      : '';
  const badgeRuleValueListApiPath =
    parsedContext && typeof parsedContext.badgeRuleValueListApiPath === 'string'
      ? parsedContext.badgeRuleValueListApiPath
      : '';
  const badgeRuleReviewQueueApiPath =
    parsedContext && typeof parsedContext.badgeRuleReviewQueueApiPath === 'string'
      ? parsedContext.badgeRuleReviewQueueApiPath
      : '';
  const assertionsApiPathPrefix =
    parsedContext && typeof parsedContext.assertionsApiPathPrefix === 'string'
      ? parsedContext.assertionsApiPathPrefix
      : '';
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
  const tenantMemberEmailsByUserId =
    parsedContext &&
    parsedContext.tenantMemberEmailsByUserId &&
    typeof parsedContext.tenantMemberEmailsByUserId === 'object'
      ? parsedContext.tenantMemberEmailsByUserId
      : {};
  if (
    tenantAdminPath.length === 0 ||
    manualIssueApiPath.length === 0 ||
    badgeRuleApiPath.length === 0 ||
    badgeRuleValueListApiPath.length === 0 ||
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
  const manualIssueForm = document.getElementById('manual-issue-form');
  const manualIssueStatus = document.getElementById('manual-issue-status');
  const ruleCreateForm = document.getElementById('rule-create-form');
  const ruleCreateStatus = document.getElementById('rule-create-status');
  const ruleEvaluateForm = document.getElementById('rule-evaluate-form');
  const ruleEvaluateStatus = document.getElementById('rule-evaluate-status');
  const ruleActionStatus = document.getElementById('rule-action-status');
  const ruleValueListForm = document.getElementById('rule-value-list-form');
  const ruleValueListStatus = document.getElementById('rule-value-list-status');
  const ruleValueListBody = document.getElementById('rule-value-list-body');
  const ruleReviewQueueRefreshButton = document.getElementById('rule-review-queue-refresh');
  const ruleReviewQueueStatus = document.getElementById('rule-review-queue-status');
  const ruleReviewQueueBody = document.getElementById('rule-review-queue-body');
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
  }

  async function loadRuleValueLists(statusElement, options = {}) {
    const quietSuccess = options && options.quietSuccess === true;

    if (statusElement instanceof HTMLElement && !quietSuccess) {
      setStatus(statusElement, 'Loading reusable lists...', false);
    }

    if (ruleValueListBody instanceof HTMLElement) {
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
    } catch {
      setStatus(
        ruleReviewQueueStatus,
        'Unable to resolve review queue entry from this browser session.',
        true,
      );
    }
  }

  const loadAssertionLifecycle = async (
    assertionId,
    statusElement,
    outputElement = assertionLifecycleOutput,
  ) => {
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

    setCodeOutput(outputElement, '');

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

      setCodeOutput(outputElement, JSON.stringify(payload, null, 2));
      fillLifecycleAssertionIdInputs(normalizedAssertionId);
      return payload;
    } catch {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Unable to load lifecycle state from this browser session.', true);
      }

      return null;
    }
  };
  const transitionAssertionLifecycle = async ({
    assertionId,
    toState,
    reasonCode,
    reason,
    statusElement,
  }) => {
    const normalizedAssertionId = typeof assertionId === 'string' ? assertionId.trim() : '';
    const normalizedToState = typeof toState === 'string' ? toState.trim() : '';
    const normalizedReasonCode = typeof reasonCode === 'string' ? reasonCode.trim() : '';
    const normalizedReason = typeof reason === 'string' ? reason.trim() : '';

    if (
      normalizedAssertionId.length === 0 ||
      normalizedToState.length === 0 ||
      normalizedReasonCode.length === 0
    ) {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Assertion, target state, and reason code are required.', true);
      }

      return null;
    }

    if (statusElement instanceof HTMLElement) {
      setStatus(statusElement, 'Applying lifecycle transition...', false);
    }

    try {
      const response = await fetch(
        assertionsApiPathPrefix +
          '/' +
          encodeURIComponent(normalizedAssertionId) +
          '/lifecycle/transition',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            toState: normalizedToState,
            reasonCode: normalizedReasonCode,
            ...(normalizedReason.length > 0 ? { reason: normalizedReason } : {}),
          }),
        },
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        if (statusElement instanceof HTMLElement) {
          setStatus(statusElement, errorDetailFromPayload(payload), true);
        }

        return null;
      }

      const status = payload && typeof payload.status === 'string' ? payload.status : 'updated';
      const currentState =
        payload && typeof payload.currentState === 'string' ? payload.currentState : normalizedToState;

      if (statusElement instanceof HTMLElement) {
        setStatus(
          statusElement,
          'Lifecycle transition result: status=' + status + ', currentState=' + currentState + '.',
          false,
        );
      }

      return payload;
    } catch {
      if (statusElement instanceof HTMLElement) {
        setStatus(statusElement, 'Unable to apply lifecycle transition from this browser session.', true);
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

  if (ruleValueListBody instanceof HTMLElement) {
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
      } catch {
        setStatus(manualIssueStatus, 'Unable to issue badge from this browser session.', true);
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
          'Tenant member, org unit, and scoped role are required.',
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
        setStatus(delegatedGrantStatus, 'Delegate and org unit are required.', true);
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
      const data = new FormData(assertionLifecycleTransitionForm);
      const assertionIdRaw = data.get('assertionId');
      const toStateRaw = data.get('toState');
      const reasonCodeRaw = data.get('reasonCode');
      const reasonRaw = data.get('reason');
      await transitionAssertionLifecycle({
        assertionId: assertionIdRaw,
        toState: toStateRaw,
        reasonCode: reasonCodeRaw,
        reason: reasonRaw,
        statusElement: assertionLifecycleTransitionStatus,
      });
    });
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
