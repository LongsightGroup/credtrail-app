export const INSTITUTION_ADMIN_RULE_BUILDER_SETUP_JS = `
  if (
    ruleCreateForm instanceof HTMLFormElement &&
    ruleCreateStatus instanceof HTMLElement &&
    ruleBuilderConditionList instanceof HTMLElement &&
    ruleBuilderRootLogic instanceof HTMLInputElement &&
    ruleBuilderDefinitionJson instanceof HTMLTextAreaElement
  ) {
    const badgeRulePreviewApiPath = badgeRuleApiPath + '/preview-evaluate';
    const ruleBuilderDraftStorageKey = 'credtrail:rule-builder:' + tenantAdminPath;
    const ruleBuilderContext =
      parsedContext &&
      parsedContext.ruleBuilderContext &&
      typeof parsedContext.ruleBuilderContext === 'object'
        ? parsedContext.ruleBuilderContext
        : null;
    const badgeTemplateCourseMap = new Map();
    const badgeTemplatesContext =
      ruleBuilderContext && Array.isArray(ruleBuilderContext.badgeTemplates)
        ? ruleBuilderContext.badgeTemplates
        : [];

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
      const match = courseId.match(/^(.+?)(\\d+)([A-Z]?)$/i);

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
                courseId: primaryCourseId,
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
                courseId: primaryCourseId,
                requireCompleted: true,
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
                courseId: nextCourseId,
                requireCompleted: true,
              },
            ],
          },
        },
      };
    };
    let runRuleBuilderTest = async () => {};
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

    let ruleNameManuallyEdited = false;

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

      return badgeLabel + ' \u2013 ' + patternName;
    };

    const syncSuggestedRuleName = () => {
      if (ruleNameManuallyEdited) {
        return;
      }

      const suggestedName = buildSuggestedRuleName();
      setRuleCreateFieldValue('name', suggestedName);

      if (ruleBuilderNameVisible instanceof HTMLInputElement) {
        ruleBuilderNameVisible.value = suggestedName;
      }
    };
`;
