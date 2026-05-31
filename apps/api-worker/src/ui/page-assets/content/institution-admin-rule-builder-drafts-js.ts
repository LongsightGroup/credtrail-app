export const INSTITUTION_ADMIN_RULE_BUILDER_DRAFTS_JS = `
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
        syncSuggestedRuleName();
        syncRuleBuilderSummary('Blank requirements started.');
        return;
      }

      const selectedTemplate =
        buildDefaultTemplateDefinitions(getDefaultCourseId())[presetKey] ??
        buildDefaultTemplateDefinitions(getDefaultCourseId()).course_and_grade;
      ruleBuilderDefinitionJson.value = JSON.stringify(selectedTemplate, null, 2);
      applyDefinitionToBuilder(selectedTemplate, 'Template');
      syncSuggestedRuleName();
    };

    const applyTestFactPreset = () => {
      const presetKey =
        ruleBuilderTemplatePreset instanceof HTMLSelectElement
          ? ruleBuilderTemplatePreset.value.trim()
          : ruleBuilderTestPresetSelect instanceof HTMLSelectElement
            ? ruleBuilderTestPresetSelect.value.trim()
            : 'canvas_course_grade';
      const learnerId = getTextFieldValue('testLearnerId') || 'canvas:12345';
      const recipientIdentity = getTextFieldValue('testRecipientIdentity') || 'learner@example.edu';
      const courseId = getDefaultCourseId() || getCoursePlaceholder();
      const programCourseIds = deriveRelatedCourseIds(courseId, 3);
      const nextCourseId = programCourseIds[1] ?? courseId + '-2';
      const surveyId = courseId + '_EXIT_SURVEY';

      setRuleCreateFieldValue('testLearnerId', learnerId);
      setRuleCreateFieldValue('testRecipientIdentity', recipientIdentity);

      if (presetKey === 'program_completion') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              completions: programCourseIds.map((entry) => {
                return {
                  courseId: entry,
                  learnerId,
                  completed: true,
                  completionPercent: 100,
                };
              }),
            },
            null,
            2,
          ),
        );
      } else if (presetKey === 'assignment_submission') {
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '88');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              submissions: [
                {
                  courseId,
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
      } else if (presetKey === 'prerequisite_chain' || presetKey === 'prerequisite_badge') {
        setRuleCreateFieldValue('testCourseId', nextCourseId);
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
        setRuleCreateFieldValue('testCourseId', courseId);
        setRuleCreateFieldValue('testFinalScore', '92');
        setRuleCreateFieldValue(
          'testFactsJson',
          JSON.stringify(
            {
              surveyCompletions: [
                {
                  surveyId,
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
        setRuleCreateFieldValue('testCourseId', courseId);
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
        setRuleCreateFieldValue('testCourseId', courseId);
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
            tryNavigateToStep(targetIndex);
          }
        });
      });
    }

    if (ruleBuilderStepNextButton instanceof HTMLButtonElement) {
      ruleBuilderStepNextButton.addEventListener('click', () => {
        const currentStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';

        if (!isStepComplete(currentStep)) {
          showStepGateMessage(currentStep);
          return;
        }

        tryNavigateToStep(activeRuleBuilderStepIndex + 1);
      });
    }

    if (ruleBuilderReturnToPatternButton instanceof HTMLButtonElement) {
      ruleBuilderReturnToPatternButton.addEventListener('click', () => {
        tryNavigateToStep(0);
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
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
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
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
          scoreField: 'final_score',
          minScore: 80,
          negate: false,
        });
        syncDefinitionJsonFromBuilder();
        syncRuleBuilderSummary('Alternative earning path added.');
      });
    }

    if (ruleBuilderRequireEveryRequirementButton instanceof HTMLButtonElement) {
      ruleBuilderRequireEveryRequirementButton.addEventListener('click', () => {
        setRuleBuilderRootLogic('all');
        syncDefinitionJsonFromBuilder();
        syncRuleBuilderSummary('Learner must meet every requirement.');
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
            'lmsConnectionId' in parsed &&
            typeof parsed.lmsConnectionId === 'string'
          ) {
            setRuleCreateFieldValue('lmsConnectionId', parsed.lmsConnectionId);
            syncSelectedLmsProviderKind();
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
            lmsConnectionId: getTextFieldValue('lmsConnectionId'),
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
          setStatus(ruleCreateStatus, 'Select a rule to copy.', true);
          syncRuleBuilderSummary('Select a rule to copy.');
          return;
        }

        setStatus(ruleCreateStatus, 'Copying rule settings...', false);
        syncRuleBuilderSummary('Copying rule settings...');

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

          if (rule && typeof rule.description === 'string' && rule.description.length > 0) {
            setRuleCreateFieldValue('description', rule.description);
          }

          if (rule && typeof rule.badgeTemplateId === 'string') {
            setRuleCreateFieldValue('badgeTemplateId', rule.badgeTemplateId);
          }

          if (rule && typeof rule.lmsConnectionId === 'string') {
            setRuleCreateFieldValue('lmsConnectionId', rule.lmsConnectionId);
            syncSelectedLmsProviderKind();
          }

          if (latestVersion && typeof latestVersion.ruleJson === 'string') {
            const definition = JSON.parse(latestVersion.ruleJson);
            ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
            applyDefinitionToBuilder(definition, 'Copied rule settings');
          } else {
            setStatus(ruleCreateStatus, 'Selected rule has no saved settings to copy.', true);
            syncRuleBuilderSummary('Selected rule has no saved settings to copy.');
          }
        } catch {
          setStatus(ruleCreateStatus, 'Unable to copy selected rule from this browser session.', true);
          syncRuleBuilderSummary('Unable to copy selected rule from this browser session.');
        }
      });
    }
`;
