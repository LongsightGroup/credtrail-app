export const INSTITUTION_ADMIN_ISSUED_BADGES_JS = `
(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  let parsedContext;

  try {
    parsedContext = JSON.parse(contextElement.dataset.contextJson ?? '{}');
  } catch {
    return;
  }

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
  const issuedBadgesFilterForm = document.getElementById('issued-badges-filter-form');
  const issuedBadgesStatus = document.getElementById('issued-badges-status');
  const issuedBadgesBody = document.getElementById('issued-badges-body');
  const issuedBadgesActionStatus = document.getElementById('issued-badges-action-status');
  const issuedBadgeLifecyclePanel = document.getElementById('issued-badge-lifecycle-panel');
  const issuedBadgeLifecycleTitle = document.getElementById('issued-badge-lifecycle-title');
  const issuedBadgeLifecycleClose = document.getElementById('issued-badge-lifecycle-close');
  const issuedBadgeLifecycleStatus = document.getElementById('issued-badge-lifecycle-status');
  const issuedBadgeLifecycleOutput = document.getElementById('issued-badge-lifecycle-output');
  const issuedBadgeRevokeForm = document.getElementById('issued-badge-revoke-form');

  if (
    assertionsApiPathPrefix.length === 0 ||
    issuedBadgeRowsPath.length === 0 ||
    !(issuedBadgesFilterForm instanceof HTMLFormElement) ||
    !(issuedBadgesStatus instanceof HTMLElement) ||
    !(issuedBadgesBody instanceof HTMLElement) ||
    !(issuedBadgesActionStatus instanceof HTMLElement)
  ) {
    return;
  }

  const setStatus = (el, text, isError, tone = 'info') => {
    if (!(el instanceof HTMLElement)) {
      return;
    }

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
  const escapeHtml = (value) => {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
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
  const setIssuedBadgesEmptyState = (message) => {
    issuedBadgesBody.innerHTML =
      '<tr><td colspan="6" class="ct-admin__empty">' + escapeHtml(message) + '</td></tr>';
  };
  const loadAssertionLifecycle = async (assertionId, statusElement, outputElement) => {
    const normalizedAssertionId =
      typeof assertionId === 'string' ? assertionId.trim() : '';

    if (normalizedAssertionId.length === 0) {
      setStatus(statusElement, 'Assertion ID is required.', true);
      return null;
    }

    setStatus(statusElement, 'Loading lifecycle state...', false);
    setCodeOutput(outputElement, '');

    try {
      const response = await fetch(
        assertionsApiPathPrefix + '/' + encodeURIComponent(normalizedAssertionId) + '/lifecycle',
      );
      const payload = await parseJsonBody(response);

      if (!response.ok) {
        setStatus(statusElement, errorDetailFromPayload(payload), true);
        return null;
      }

      const state = payload && typeof payload.state === 'string' ? payload.state : 'unknown';
      const source = payload && typeof payload.source === 'string' ? payload.source : 'unknown';
      const eventCount = payload && Array.isArray(payload.events) ? payload.events.length : 0;
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
      setCodeOutput(outputElement, JSON.stringify(payload, null, 2));
      return payload;
    } catch {
      setStatus(statusElement, 'Unable to load lifecycle state from this browser session.', true);
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
      setStatus(statusElement, 'Assertion, target state, and reason code are required.', true);
      return null;
    }

    setStatus(statusElement, 'Applying lifecycle transition...', false);

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
        setStatus(statusElement, errorDetailFromPayload(payload), true);
        return null;
      }

      const state = payload && typeof payload.toState === 'string' ? payload.toState : normalizedToState;
      setStatus(statusElement, 'Lifecycle transition recorded: ' + state + '.', false);
      return payload;
    } catch {
      setStatus(statusElement, 'Unable to apply lifecycle transition from this browser session.', true);
      return null;
    }
  };
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
  const closeIssuedActionMenuPopover = (element) => {
    if (!(element instanceof Element)) {
      return;
    }
    const popover = element.closest('.ct-admin__action-menu-popover');
    if (popover instanceof HTMLElement && typeof popover.hidePopover === 'function') {
      popover.hidePopover();
    }
  };
  const positionIssuedActionMenuPopover = (popover, trigger) => {
    if (!(popover instanceof HTMLElement) || !(trigger instanceof HTMLElement)) {
      return;
    }
    const rect = trigger.getBoundingClientRect();
    popover.style.position = 'fixed';
    popover.style.top = rect.bottom + 4 + 'px';
    popover.style.right = window.innerWidth - rect.right + 'px';
    popover.style.left = 'auto';
    popover.style.bottom = 'auto';
  };
  document.addEventListener('pointerdown', (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }
    const trigger = event.target.closest('[popovertarget]');
    if (!(trigger instanceof HTMLElement)) {
      return;
    }
    const popoverId = trigger.getAttribute('popovertarget');
    if (popoverId === null || popoverId.length === 0) {
      return;
    }
    const popover = document.getElementById(popoverId);
    if (popover instanceof HTMLElement && popover.classList.contains('ct-admin__action-menu-popover')) {
      positionIssuedActionMenuPopover(popover, trigger);
    }
  });
  const openIssuedBadgeLifecyclePanel = (assertionId, mode) => {
    if (!(issuedBadgeLifecyclePanel instanceof HTMLElement)) {
      return false;
    }

    issuedBadgeLifecyclePanel.hidden = false;

    if (issuedBadgeLifecycleTitle instanceof HTMLElement) {
      issuedBadgeLifecycleTitle.textContent =
        mode === 'revoke'
          ? 'Review revocation for ' + assertionId
          : 'Lifecycle audit for ' + assertionId;
    }

    if (issuedBadgeRevokeForm instanceof HTMLFormElement) {
      issuedBadgeRevokeForm.reset();
      issuedBadgeRevokeForm.hidden = mode !== 'revoke';

      const assertionInput = issuedBadgeRevokeForm.elements.namedItem('assertionId');

      if (assertionInput instanceof HTMLInputElement) {
        assertionInput.value = assertionId;
      }
    }

    if (issuedBadgeLifecycleStatus instanceof HTMLElement) {
      setStatus(
        issuedBadgeLifecycleStatus,
        mode === 'revoke'
          ? 'Review lifecycle state, enter a reason, then revoke the badge.'
          : 'Loading lifecycle audit...',
        false,
        mode === 'revoke' ? 'warning' : 'info',
      );
    }

    setCodeOutput(issuedBadgeLifecycleOutput, '');
    issuedBadgeLifecyclePanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    return true;
  };

  issuedBadgesFilterForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    await loadIssuedBadges();
  });

  if (issuedBadgeLifecycleClose instanceof HTMLButtonElement) {
    issuedBadgeLifecycleClose.addEventListener('click', () => {
      if (issuedBadgeLifecyclePanel instanceof HTMLElement) {
        issuedBadgeLifecyclePanel.hidden = true;
      }
    });
  }

  if (
    issuedBadgeRevokeForm instanceof HTMLFormElement &&
    issuedBadgeLifecycleStatus instanceof HTMLElement
  ) {
    issuedBadgeRevokeForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const data = new FormData(issuedBadgeRevokeForm);
      const assertionIdRaw = data.get('assertionId');
      const reasonCodeRaw = data.get('reasonCode');
      const reasonRaw = data.get('reason');
      const assertionId = typeof assertionIdRaw === 'string' ? assertionIdRaw.trim() : '';
      const result = await transitionAssertionLifecycle({
        assertionId,
        toState: 'revoked',
        reasonCode: reasonCodeRaw,
        reason: reasonRaw,
        statusElement: issuedBadgeLifecycleStatus,
      });

      if (result === null) {
        return;
      }

      issuedBadgeRevokeForm.hidden = true;
      setStatus(issuedBadgesActionStatus, 'Assertion revoked: ' + assertionId + '.', false);
      await loadAssertionLifecycle(assertionId, issuedBadgeLifecycleStatus, issuedBadgeLifecycleOutput);
      await loadIssuedBadges();
    });
  }

  issuedBadgesBody.addEventListener('click', async (event) => {
    const target = event.target;

    if (!(target instanceof HTMLElement)) {
      return;
    }

    const menuLink = target.closest('a.ct-admin__action-menu-item');

    if (menuLink instanceof HTMLAnchorElement) {
      closeIssuedActionMenuPopover(menuLink);
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

    closeIssuedActionMenuPopover(actionButton);

    if (action === 'audit') {
      setStatus(issuedBadgesActionStatus, 'Loading lifecycle audit for ' + assertionId + '...', false);
      openIssuedBadgeLifecyclePanel(assertionId, 'audit');
      const lifecyclePayload = await loadAssertionLifecycle(
        assertionId,
        issuedBadgeLifecycleStatus,
        issuedBadgeLifecycleOutput,
      );

      if (lifecyclePayload === null) {
        setStatus(issuedBadgesActionStatus, 'Unable to load lifecycle audit.', true);
        return;
      }

      setStatus(issuedBadgesActionStatus, 'Lifecycle audit loaded for ' + assertionId + '.', false);
      return;
    }

    if (action === 'revoke') {
      setStatus(issuedBadgesActionStatus, 'Review revocation details for ' + assertionId + '.', false);
      openIssuedBadgeLifecyclePanel(assertionId, 'revoke');
      await loadAssertionLifecycle(assertionId, issuedBadgeLifecycleStatus, issuedBadgeLifecycleOutput);
    }
  });

  void loadIssuedBadges();
})();
`;
