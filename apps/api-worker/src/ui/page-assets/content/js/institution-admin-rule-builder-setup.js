
  if (
    ruleCreateForm instanceof HTMLFormElement &&
    ruleCreateStatus instanceof HTMLElement &&
    ruleBuilderConditionList instanceof HTMLElement &&
    ruleBuilderRootLogic instanceof HTMLInputElement &&
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement
  ) {
    const badgeRulePreviewApiPath = badgeRuleApiPath + '/preview-evaluate';
    const ruleBuilderContext =
      parsedContext &&
      parsedContext.ruleBuilderContext &&
      typeof parsedContext.ruleBuilderContext === 'object'
        ? parsedContext.ruleBuilderContext
        : null;
    const editRuleContext =
      ruleBuilderContext &&
      ruleBuilderContext.editRule &&
      typeof ruleBuilderContext.editRule === 'object' &&
      !Array.isArray(ruleBuilderContext.editRule) &&
      typeof ruleBuilderContext.editRule.id === 'string'
        ? ruleBuilderContext.editRule
        : null;
    const builderDraftContext =
      ruleBuilderContext &&
      ruleBuilderContext.builderDraft &&
      typeof ruleBuilderContext.builderDraft === 'object' &&
      !Array.isArray(ruleBuilderContext.builderDraft)
        ? ruleBuilderContext.builderDraft
        : null;
    const isRuleBuilderEditMode = editRuleContext !== null;
    const ruleBuilderSubmitApiPath = isRuleBuilderEditMode
      ? badgeRuleApiPath + '/' + encodeURIComponent(editRuleContext.id) + '/draft'
      : badgeRuleApiPath;
    const ruleBuilderDraftApiPath =
      ruleBuilderContext && typeof ruleBuilderContext.badgeRuleBuilderDraftApiPath === "string"
        ? ruleBuilderContext.badgeRuleBuilderDraftApiPath
        : "";
    const badgeTemplateCourseMap = new Map();
    const badgeTemplatesContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.badgeTemplates)
        ? ruleBuilderContext.badgeTemplates
        : [];
    const lmsConnectionsContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.lmsConnections)
        ? ruleBuilderContext.lmsConnections
        : [];
    const lmsConnectionsById = new Map();

    badgeTemplatesContext.forEach((entry) => {
      if (entry && typeof entry.id === 'string') {
        badgeTemplateCourseMap.set(
          entry.id,
          typeof entry.defaultCourseId === 'string' && entry.defaultCourseId.length > 0
            ? entry.defaultCourseId
            : null,
        );
      }
    });

    lmsConnectionsContext.forEach((entry) => {
      if (entry && typeof entry.id === 'string') {
        lmsConnectionsById.set(entry.id, entry);
      }
    });

    const getSelectedLmsConnectionId = () => {
      return getTextFieldValue('lmsConnectionId');
    };

    const getSelectedLmsConnection = () => {
      const connectionId = getSelectedLmsConnectionId();
      return connectionId.length > 0 ? lmsConnectionsById.get(connectionId) ?? null : null;
    };

    const getSelectedLmsProviderKind = () => {
      const connection = getSelectedLmsConnection();
      return connection && typeof connection.providerKind === 'string'
        ? connection.providerKind
        : getTextFieldValue('lmsProviderKind');
    };

    const syncSelectedLmsProviderKind = () => {
      const connection = getSelectedLmsConnection();
      const providerKind =
        connection && typeof connection.providerKind === 'string' ? connection.providerKind : '';

      if (ruleBuilderLmsProviderKindInput instanceof HTMLInputElement) {
        ruleBuilderLmsProviderKindInput.value = providerKind;
      }
    };

    const fallbackCourseId =
      ruleBuilderContext &&
      typeof ruleBuilderContext.fallbackCourseId === 'string' &&
      ruleBuilderContext.fallbackCourseId.length > 0
        ? ruleBuilderContext.fallbackCourseId
        : '';

    const getSelectedBadgeTemplateId = () => {
      return getTextFieldValue('badgeTemplateId');
    };

    const deriveRelatedCourseIds = (courseId, count) => {
      const ids = [courseId];
      const match = courseId.match(/^(.+?)(\d+)([A-Z]?)$/i);

      if (match) {
        const prefix = match[1];
        const number = Number(match[2]);
        const suffix = match[3] ?? '';

        for (let index = 1; index < count; index += 1) {
          ids.push(prefix + String(number + index) + suffix);
        }

        return ids;
      }

      for (let index = 1; index < count; index += 1) {
        ids.push(courseId + '-' + String(index + 1));
      }

      return ids;
    };

    const getDefaultCourseId = () => {
      const templateId = getSelectedBadgeTemplateId();
      const fromTemplate =
        templateId.length > 0 ? badgeTemplateCourseMap.get(templateId) : null;

      if (typeof fromTemplate === 'string' && fromTemplate.length > 0) {
        return fromTemplate;
      }

      if (fallbackCourseId.length > 0) {
        return fallbackCourseId;
      }

      return '';
    };

    const getCoursePlaceholder = () => {
      const courseId = getDefaultCourseId();

      return courseId.length > 0 ? courseId : 'COURSE_ID';
    };

    const buildDefaultTemplateDefinitions = (courseId) => {
      const primaryCourseId = courseId.length > 0 ? courseId : 'COURSE_ID';
      const programCourseIds = deriveRelatedCourseIds(primaryCourseId, 3);
      const nextCourseId = programCourseIds[1] ?? primaryCourseId + '-2';
      const surveyId = primaryCourseId + '_EXIT_SURVEY';

      return {
        blank: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
        course_completion: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
        course_and_grade: {
          conditions: {
            all: [
              {
                type: 'course_completion',
                courseId: primaryCourseId,
                minCompletionPercent: 100,
              },
              {
                type: 'grade_threshold',
                courseId: primaryCourseId,
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
                courseIds: programCourseIds,
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
                courseId: primaryCourseId,
                assignmentId: '',
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
                surveyId,
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
                courseId: primaryCourseId,
                minCompletionPercent: 100,
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
                courseId: nextCourseId,
                minCompletionPercent: 100,
              },
            ],
          },
        },
      };
    };
    let runRuleBuilderTest = async () => {};
    const conditionTypeLabels = {
      course_completion: 'Course completion',
      grade_threshold: 'Grade threshold',
      program_completion: 'Course pathway completion',
      assignment_submission: 'Gradebook item submitted',
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
      syncRootLogicToolbarVisibility();
    };
    const conditionTypeHelpText = {
      course_completion:
        'Learner must complete all gradebook items, or a configured percentage of them.',
      grade_threshold:
        'Learner score must meet the configured minimum and/or maximum threshold.',
      program_completion:
        'Learner must complete enough courses in a course pathway.',
      assignment_submission:
        'Learner must submit an assignment, assessment, or gradebook item, with optional score constraints.',
      survey_completion:
        'Learner must complete a required survey, such as an exit survey or attestation.',
      time_window:
        'Badge can only be earned inside the configured date-time window.',
      prerequisite_badge:
        'Learner must already hold a specific prerequisite badge.',
      custom_field:
        'Learner must match an institution-specific field from imported or connected data.',
    };

    function syncExclusiveFieldPair(card, valueFieldName, listFieldName) {
      const valueField = card.querySelector('[data-field="' + valueFieldName + '"]');
      const listField = card.querySelector('[data-field="' + listFieldName + '"]');
      const readExclusiveValue = (field) => {
        if (field instanceof HTMLSelectElement && field.multiple) {
          return Array.from(field.selectedOptions)
            .map((option) => option.value.trim())
            .filter((value) => value.length > 0)
            .join(',');
        }

        if (
          field instanceof HTMLInputElement ||
          field instanceof HTMLTextAreaElement ||
          field instanceof HTMLSelectElement
        ) {
          return field.value.trim();
        }

        return '';
      };
      const valueFieldText =
        valueField instanceof HTMLInputElement ||
        valueField instanceof HTMLTextAreaElement ||
        valueField instanceof HTMLSelectElement
          ? readExclusiveValue(valueField)
          : '';
      const listFieldText = listField instanceof HTMLSelectElement ? listField.value.trim() : '';

      if (
        !(
          valueField instanceof HTMLInputElement ||
          valueField instanceof HTMLTextAreaElement ||
          valueField instanceof HTMLSelectElement
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
          valueField instanceof HTMLInputElement ||
          valueField instanceof HTMLTextAreaElement ||
          valueField instanceof HTMLSelectElement
        ) ||
        !(listField instanceof HTMLSelectElement)
      ) {
        return;
      }

      const syncPair = () => {
        syncExclusiveFieldPair(card, valueFieldName, listFieldName);
      };

      valueField.addEventListener('input', syncPair);
      valueField.addEventListener('change', syncPair);
      listField.addEventListener('change', syncPair);
      syncPair();
    }


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

    const getRuleBuilderTestDataSource = () => {
      const checkedInput = ruleBuilderTestDataSourceInputs.find((candidate) => candidate.checked);

      return checkedInput instanceof HTMLInputElement && checkedInput.value === 'example'
        ? 'example'
        : 'lms';
    };

    const syncRuleBuilderTestDataSource = () => {
      const useExampleData = getRuleBuilderTestDataSource() === 'example';

      if (ruleBuilderLiveTestFields instanceof HTMLElement) {
        ruleBuilderLiveTestFields.hidden = useExampleData;
      }

      if (ruleBuilderExampleTestFields instanceof HTMLElement) {
        ruleBuilderExampleTestFields.hidden = !useExampleData;
      }

      if (ruleBuilderExampleTestAdvanced instanceof HTMLElement) {
        ruleBuilderExampleTestAdvanced.hidden = !useExampleData;
      }

      if (useExampleData) {
        if (getTextFieldValue('testLearnerId').length === 0) {
          setRuleCreateFieldValue('testLearnerId', 'example-learner');
        }

        if (getTextFieldValue('testRecipientIdentity').length === 0) {
          setRuleCreateFieldValue('testRecipientIdentity', 'learner@example.edu');
        }
      } else {
        if (getTextFieldValue('testLearnerId') === 'example-learner') {
          setRuleCreateFieldValue('testLearnerId', '');
        }

        if (getTextFieldValue('testRecipientIdentity') === 'learner@example.edu') {
          setRuleCreateFieldValue('testRecipientIdentity', '');
        }
      }
    };

    const invalidateRuleBuilderTest = () => {
      ruleBuilderLastTestSummary = 'Not run';
      resetConditionEvaluationResults();
      syncRuleBuilderSummary('Test data changed. Run the test again.');
    };

    [
      'testLearnerId',
      'testRecipientIdentity',
      'testFinalScore',
      'testCompletionPercent',
      'testFactsJson',
    ].forEach((fieldName) => {
      const field = getRuleCreateField(fieldName);

      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        field.addEventListener('input', invalidateRuleBuilderTest);
      }
    });

    ruleBuilderTestDataSourceInputs.forEach((candidate) => {
      candidate.addEventListener('change', () => {
        syncRuleBuilderTestDataSource();
        invalidateRuleBuilderTest();
        setStatus(
          ruleBuilderTestResult,
          getRuleBuilderTestDataSource() === 'example'
            ? 'Run the test to check the rule with generated example data.'
            : 'Enter an existing LMS learner ID and recipient email, then run the test.',
          false,
        );
      });
    });

    syncRuleBuilderTestDataSource();

    const getSelectedOptionLabel = (field) => {
      if (!(field instanceof HTMLSelectElement)) {
        return '';
      }

      const selectedOption = field.selectedOptions[0];

      if (!(selectedOption instanceof HTMLOptionElement)) {
        return '';
      }

      const optionText = selectedOption.textContent?.trim() ?? '';

      if (optionText.length === 0) {
        return '';
      }

      const templateIdSuffixIndex = optionText.lastIndexOf(' (');

      if (templateIdSuffixIndex > 0) {
        return optionText.slice(0, templateIdSuffixIndex).trim();
      }

      return optionText;
    };

    const buildSuggestedRuleName = () => {
      const badgeTitle = getSelectedOptionLabel(getRuleCreateField('badgeTemplateId'));
      const patternLabel = getSelectedOptionLabel(ruleBuilderTemplatePreset);
      const badgeLabel = badgeTitle.length > 0 ? badgeTitle : 'Badge rule';
      const patternName = patternLabel.length > 0 ? patternLabel : 'Awarding rule';

      return badgeLabel + ' – ' + patternName;
    };

    const syncSuggestedRuleName = () => {
      const ruleNameField = getRuleCreateField('name');

      if (
        ruleNameField instanceof HTMLInputElement &&
        ruleNameField.dataset.ruleBuilderPreserveName === 'true' &&
        ruleNameField.value.trim().length > 0
      ) {
        return;
      }

      const suggestedName = buildSuggestedRuleName();
      setRuleCreateFieldValue('name', suggestedName);
    };
