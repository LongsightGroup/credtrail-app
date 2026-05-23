export const INSTITUTION_ADMIN_RULE_OPERATIONS_JS = `
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
`;
