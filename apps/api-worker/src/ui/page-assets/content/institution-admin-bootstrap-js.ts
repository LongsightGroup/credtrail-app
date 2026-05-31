export const INSTITUTION_ADMIN_BOOTSTRAP_JS = `
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
`;
