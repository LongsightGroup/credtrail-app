
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
      const lmsConnectionId = getTextFieldValue('lmsConnectionId');
      const sampleFinalScoreText = getTextFieldValue('testFinalScore');
      const testFactsJson = getTextFieldValue('testFactsJson');

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

      if (lmsConnectionId.length === 0) {
        const message = 'Select an LMS connection before testing the rule.';
        setStatus(ruleCreateStatus, message, true);
        if (ruleBuilderTestResult instanceof HTMLElement) {
          setStatus(ruleBuilderTestResult, message, true);
        }
        ruleBuilderLastTestSummary = 'Missing LMS connection';
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
      } else {
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

        facts = buildSampleFactsFromConditions(readConditionsForPreview());
      }

      try {
        const response = await fetch(badgeRulePreviewApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            definition,
            lmsConnectionId,
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

    ruleCreateForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const savingMessage = isRuleBuilderEditMode ? 'Saving rule changes...' : 'Creating rule draft...';
      setStatus(ruleCreateStatus, savingMessage, false);
      setCodeOutput(ruleBuilderTestOutput, '');
      syncRuleBuilderSummary(savingMessage);

      const name = getTextFieldValue('name');
      const description = getTextFieldValue('description');
      const badgeTemplateId = getTextFieldValue('badgeTemplateId');
      const lmsConnectionId = getTextFieldValue('lmsConnectionId');
      const issuanceTiming = getTextFieldValue('issuanceTiming');
      const changeSummaryInput = getTextFieldValue('changeSummary');

      if (name.length === 0 || badgeTemplateId.length === 0 || lmsConnectionId.length === 0) {
        setStatus(
          ruleCreateStatus,
          'Rule name, badge template, and LMS connection are required.',
          true,
        );
        syncRuleBuilderSummary(
          'Rule name, badge template, and LMS connection are required.',
        );
        return;
      }

      let definition;

      try {
        definition = parseDefinitionJson();
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
        changeSummary =
          (isRuleBuilderEditMode
            ? 'New draft version saved via visual builder; issuance timing: '
            : 'Rule created via visual builder; issuance timing: ') +
          issuanceLabel +
          '.';
      } else if (!changeSummary.toLowerCase().includes('issuance timing')) {
        changeSummary =
          changeSummary + ' Issuance timing: ' + issuanceLabel + '.';
      }

      try {
        const response = await fetch(ruleBuilderSubmitApiPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
          },
          body: JSON.stringify({
            name,
            ...(description.length > 0 ? { description } : {}),
            badgeTemplateId,
            lmsConnectionId,
            definition: definitionWithOptions,
            ...(changeSummary.length > 0 ? { changeSummary } : {}),
          }),
        });
        const payload = await parseJsonBody(response);

        if (!response.ok) {
          setStatus(ruleCreateStatus, errorDetailFromPayload(payload), true);
          syncRuleBuilderSummary(errorDetailFromPayload(payload));
          return;
        }

        const successMessage = isRuleBuilderEditMode
          ? 'New draft version saved.'
          : 'Rule draft created.';
        setStatus(
          ruleCreateStatus,
          successMessage,
          false,
          'success',
        );
        syncRuleBuilderSummary(successMessage);
        setTimeout(() => {
          window.location.assign(rulesListPath);
        }, 900);
      } catch {
        const message = isRuleBuilderEditMode
          ? 'Unable to save rule changes from this browser session.'
          : 'Unable to create rule draft from this browser session.';
        setStatus(ruleCreateStatus, message, true);
        syncRuleBuilderSummary(message);
      }
    });

    const badgeTemplateField = getRuleCreateField('badgeTemplateId');

    if (badgeTemplateField instanceof HTMLSelectElement) {
      badgeTemplateField.addEventListener('change', () => {
        syncSuggestedRuleName();
        syncRuleBuilderSummary();

        if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
          applyTemplatePreset();
        }
      });
    }

    if (ruleBuilderLmsConnectionSelect instanceof HTMLSelectElement) {
      ruleBuilderLmsConnectionSelect.addEventListener('change', () => {
        setLmsLookupStatus('', false);
        syncSelectedLmsProviderKind();
        refreshConditionCardValueListOptions();
        syncRuleBuilderSummary();
      });
      syncSelectedLmsProviderKind();
    }

    if (ruleBuilderTemplatePreset instanceof HTMLSelectElement) {
      ruleBuilderTemplatePreset.addEventListener('change', () => {
        applyTemplatePreset();
        syncSuggestedRuleName();
        syncRuleBuilderSummary();
      });
    }

    setBuilderStepState(0);

    if (isRuleBuilderEditMode) {
      if (typeof editRuleContext.name === 'string') {
        setRuleCreateFieldValue('name', editRuleContext.name);
      }

      if (typeof editRuleContext.description === 'string') {
        setRuleCreateFieldValue('description', editRuleContext.description);
      }

      if (typeof editRuleContext.badgeTemplateId === 'string') {
        setRuleCreateFieldValue('badgeTemplateId', editRuleContext.badgeTemplateId);
      }

      if (typeof editRuleContext.lmsConnectionId === 'string') {
        setRuleCreateFieldValue('lmsConnectionId', editRuleContext.lmsConnectionId);
        syncSelectedLmsProviderKind();
      }

      if (editRuleContext.definition && typeof editRuleContext.definition === 'object') {
        ruleBuilderDefinitionJson.value = JSON.stringify(editRuleContext.definition, null, 2);
        applyDefinitionToBuilder(editRuleContext.definition, 'Saved rule settings');
      } else {
        setStatus(ruleCreateStatus, 'Saved rule JSON could not be loaded into the builder.', true);
        syncRuleBuilderSummary('Saved rule JSON could not be loaded into the builder.');
      }
    } else {
      syncSuggestedRuleName();
      applyTemplatePreset();
    }

    refreshConditionCardValueListOptions();
    syncRuleBuilderSummary();
  }
