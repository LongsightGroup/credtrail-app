export const INSTITUTION_ADMIN_RULE_BUILDER_SUBMIT_JS = `
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
