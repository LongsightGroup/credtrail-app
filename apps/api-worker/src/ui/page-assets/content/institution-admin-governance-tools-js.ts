export const INSTITUTION_ADMIN_GOVERNANCE_TOOLS_JS = `
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
    const postRuleAction = async (candidate, actionPath, body, actionLabel, successLabel) => {
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

        setStatus(ruleActionStatus, successLabel ?? actionLabel + ' complete.', false);
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
        const label = candidate.dataset.ruleLabel ?? 'rule';
        const confirmed = window.confirm(
          'Mark draft version for "' + label + '" ready for review? This does not activate the rule.',
        );

        if (!confirmed) {
          return;
        }

        await postRuleAction(
          candidate,
          candidate.dataset.ruleSubmitPath,
          {},
          'Marking draft ready for review',
          'Draft is ready for review. It is not active yet.',
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
`;
