export const INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELDS_JS = `
    const getConditionCards = () => {
      return Array.from(
        ruleBuilderConditionList.querySelectorAll('.ct-admin__condition-card'),
      ).filter((candidate) => candidate instanceof HTMLElement);
    };

    const readFieldFromCard = (card, fieldName) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

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

    const readCheckboxFromCard = (card, fieldName) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');
      return field instanceof HTMLInputElement ? field.checked : false;
    };

    const setFieldOnCard = (card, fieldName, value) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

      if (field instanceof HTMLSelectElement && field.multiple) {
        const values = new Set(parseCsv(String(value)));
        Array.from(field.options).forEach((option) => {
          option.selected = values.has(option.value);
        });
        return;
      }

      if (
        field instanceof HTMLInputElement ||
        field instanceof HTMLTextAreaElement ||
        field instanceof HTMLSelectElement
      ) {
        field.value = value;
      }
    };

    const setCheckboxOnCard = (card, fieldName, checked) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

      if (field instanceof HTMLInputElement) {
        field.checked = checked;
      }
    };

    const parseNumberInput = (value) => {
      if (value.trim().length === 0) {
        return null;
      }

      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    };

    const parseCsv = (value) => {
      return value
        .split(',')
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0);
    };

    const parseCustomExpectedValue = (value, valueType) => {
      if (valueType === 'number') {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : null;
      }

      if (valueType === 'boolean') {
        const normalized = value.trim().toLowerCase();

        if (normalized === 'true' || normalized === 'yes' || normalized === '1') {
          return true;
        }

        if (normalized === 'false' || normalized === 'no' || normalized === '0') {
          return false;
        }

        return null;
      }

      return value.trim().length > 0 ? value.trim() : null;
    };

    const toDateTimeLocalInput = (isoValue) => {
      if (typeof isoValue !== 'string' || isoValue.length < 16) {
        return '';
      }

      return isoValue.slice(0, 16);
    };

    const toIsoTimestamp = (value) => {
      if (value.length === 0) {
        return undefined;
      }

      const parsed = Date.parse(value);

      if (!Number.isFinite(parsed)) {
        return null;
      }

      return new Date(parsed).toISOString();
    };

    const cloneRuleBuilderConditionCard = () => {
      if (!(ruleBuilderConditionCardTemplate instanceof HTMLTemplateElement)) {
        return null;
      }

      const firstElement = ruleBuilderConditionCardTemplate.content.firstElementChild;

      if (!(firstElement instanceof HTMLElement)) {
        return null;
      }

      const clone = firstElement.cloneNode(true);

      return clone instanceof HTMLElement ? clone : null;
    };

    const updateConditionCardClass = (card, conditionType) => {
      card.classList.remove(
        'ct-admin__condition-card--course_completion',
        'ct-admin__condition-card--grade_threshold',
        'ct-admin__condition-card--program_completion',
        'ct-admin__condition-card--assignment_submission',
        'ct-admin__condition-card--survey_completion',
        'ct-admin__condition-card--time_window',
        'ct-admin__condition-card--prerequisite_badge',
        'ct-admin__condition-card--custom_field',
      );
      card.classList.add('ct-admin__condition-card--' + conditionType);
    };

    const updateConditionPlainSummary = (card) => {
      const summaryElement = card.querySelector('.ct-admin__condition-summary');

      if (!(summaryElement instanceof HTMLElement)) {
        return;
      }

      const typeSelect = card.querySelector('.ct-admin__condition-type');
      const conditionType =
        typeSelect instanceof HTMLSelectElement ? typeSelect.value : 'course_completion';
      const negatePrefix = readCheckboxFromCard(card, 'negate') ? 'Must not: ' : '';

      try {
        const condition = readConditionFromCard(card, false);
        summaryElement.textContent = negatePrefix + formatConditionPlainSummary(condition);
        return;
      } catch {
        summaryElement.textContent =
          negatePrefix + (conditionTypeLabels[conditionType] ?? 'Requirement');
      }
    };

    const formatConditionPlainSummary = (condition) => {
      if (!condition || typeof condition !== 'object' || typeof condition.type !== 'string') {
        return 'Requirement';
      }

      if (condition.type === 'course_completion') {
        const courseLabel =
          typeof condition.courseListId === 'string' && condition.courseListId.length > 0
            ? 'courses from list ' + condition.courseListId
            : typeof condition.courseId === 'string' && condition.courseId.length > 0
              ? condition.courseId
              : 'the course';
        const completionLabel =
          condition.requireCompleted === false ? 'started ' : 'completed ';
        const minPercent =
          typeof condition.minCompletionPercent === 'number'
            ? ' with at least ' + String(condition.minCompletionPercent) + '% completion'
            : '';

        return 'Learner has ' + completionLabel + courseLabel + minPercent;
      }

      if (condition.type === 'grade_threshold') {
        const courseLabel =
          typeof condition.courseListId === 'string' && condition.courseListId.length > 0
            ? 'courses from list ' + condition.courseListId
            : typeof condition.courseId === 'string' && condition.courseId.length > 0
              ? condition.courseId
              : 'the course';
        const scoreField =
          condition.scoreField === 'current_score' ? 'current score' : 'final score';
        const minScore =
          typeof condition.minScore === 'number'
            ? ' at least ' + String(condition.minScore)
            : '';
        const maxScore =
          typeof condition.maxScore === 'number'
            ? ' no more than ' + String(condition.maxScore)
            : '';

        return (
          'Learner ' +
          scoreField +
          ' in ' +
          courseLabel +
          ' is' +
          minScore +
          maxScore
        );
      }

      if (condition.type === 'program_completion') {
        const courseCount = Array.isArray(condition.courseIds) ? condition.courseIds.length : 0;
        const minimumCompleted =
          typeof condition.minimumCompleted === 'number'
            ? condition.minimumCompleted
            : courseCount;

        if (
          typeof condition.courseListId === 'string' &&
          condition.courseListId.length > 0
        ) {
          return (
            'Learner completes at least ' +
            String(minimumCompleted) +
            ' courses from list ' +
            condition.courseListId
          );
        }

        const courseLabel =
          courseCount > 0 ? condition.courseIds.join(', ') : 'required courses';

        return (
          'Learner completes at least ' +
          String(minimumCompleted) +
          ' of: ' +
          courseLabel
        );
      }

      if (condition.type === 'assignment_submission') {
        const courseLabel =
          typeof condition.courseId === 'string' && condition.courseId.length > 0
            ? condition.courseId
            : 'the course';
        const assignmentLabel =
          typeof condition.assignmentId === 'string' && condition.assignmentId.length > 0
            ? condition.assignmentId
            : 'the assignment';
        const minScore =
          typeof condition.minScore === 'number'
            ? ' with score at least ' + String(condition.minScore)
            : '';

        return (
          'Learner submits gradebook item ' +
          assignmentLabel +
          ' in ' +
          courseLabel +
          minScore
        );
      }

      if (condition.type === 'survey_completion') {
        const surveyLabel =
          typeof condition.surveyId === 'string' && condition.surveyId.length > 0
            ? condition.surveyId
            : 'the required survey';

        return 'Learner completes survey ' + surveyLabel;
      }

      if (condition.type === 'time_window') {
        const notBefore =
          typeof condition.notBefore === 'string' && condition.notBefore.length > 0
            ? ' after ' + condition.notBefore
            : '';
        const notAfter =
          typeof condition.notAfter === 'string' && condition.notAfter.length > 0
            ? ' before ' + condition.notAfter
            : '';

        return 'Badge can only be earned' + notBefore + notAfter;
      }

      if (condition.type === 'prerequisite_badge') {
        const badgeLabel =
          typeof condition.badgeTemplateListId === 'string' &&
          condition.badgeTemplateListId.length > 0
            ? 'badges from list ' + condition.badgeTemplateListId
            : typeof condition.badgeTemplateId === 'string' &&
                condition.badgeTemplateId.length > 0
              ? condition.badgeTemplateId
              : 'a prerequisite badge';

        return 'Learner already holds ' + badgeLabel;
      }

      if (condition.type === 'custom_field') {
        const fieldName =
          typeof condition.fieldName === 'string' && condition.fieldName.length > 0
            ? condition.fieldName
            : 'custom field';
        const expectedValue =
          typeof condition.expectedValue === 'string' && condition.expectedValue.length > 0
            ? condition.expectedValue
            : 'expected value';

        return (
          'Learner ' +
          fieldName +
          ' ' +
          (typeof condition.operator === 'string' ? condition.operator : 'matches') +
          ' ' +
          expectedValue
        );
      }

      return conditionTypeLabels[condition.type] ?? 'Requirement';
    };

    const setConditionResultState = (card, state, detail) => {
      card.classList.remove(
        'ct-admin__condition-card--result-pass',
        'ct-admin__condition-card--result-fail',
        'ct-admin__condition-card--result-review',
        'ct-admin__condition-card--result-idle',
      );
      card.classList.add('ct-admin__condition-card--result-' + state);

      const resultElement = card.querySelector('.ct-admin__condition-result');

      if (resultElement instanceof HTMLElement) {
        resultElement.dataset.state = state;
        resultElement.textContent = detail;
      }
    };

    const createConditionInput = (type, attributes) => {
      const input = document.createElement('input');
      input.type = type;

      Object.entries(attributes).forEach(([name, value]) => {
        if (value === true) {
          input.setAttribute(name, '');
          return;
        }

        if (value !== false && value !== null && value !== undefined) {
          input.setAttribute(name, String(value));
        }
      });

      return input;
    };

    const createConditionOption = (value, label, selected) => {
      const option = document.createElement('option');
      option.value = value;
      option.textContent = label;
      option.selected = selected;
      return option;
    };

    const createConditionSelect = (attributes, options) => {
      const select = document.createElement('select');

      Object.entries(attributes).forEach(([name, value]) => {
        if (value === true) {
          select.setAttribute(name, '');
          return;
        }

        if (value !== false && value !== null && value !== undefined) {
          select.setAttribute(name, String(value));
        }
      });

      select.append(...options);
      return select;
    };

    const createConditionField = (labelText, control, styled) => {
      const label = document.createElement('label');
      label.className = styled === false ? '' : 'ct-admin__field ct-admin__condition-field';
      label.append(labelText, control);
      return label;
    };

    const createConditionCheckbox = (fieldName, labelText, checked) => {
      const label = document.createElement('label');
      const checkbox = createConditionInput('checkbox', { 'data-field': fieldName });
      checkbox.checked = checked;
      label.className = 'ct-admin__checkbox-row ct-checkbox-row';
      label.append(checkbox, labelText);
      return label;
    };

    const replaceConditionFields = (fieldsContainer, fields) => {
      fieldsContainer.replaceChildren(...fields);
    };

    const createCourseSearchField = (targetFieldName) => {
      return createConditionField(
        'Course search',
        createConditionInput('search', {
          'data-lms-course-query': targetFieldName,
          placeholder: 'Search by title, code, or ID',
        }),
      );
    };

    const createCourseSelectField = (labelText, fieldName, selectedValue, multiple) => {
      const attributes = {
        'data-field': fieldName,
        'data-lms-course-select': true,
        multiple,
        required: multiple ? false : true,
        size: multiple ? '6' : null,
      };

      if (multiple) {
        attributes['data-selected-values'] = selectedValue;
      } else {
        attributes['data-selected-value'] = selectedValue;
      }

      return createConditionField(
        labelText,
        createConditionSelect(attributes, [createConditionOption('', 'Loading courses...', false)]),
      );
    };

    const createListSelectField = (labelText, fieldName, kind, selectedValue, emptyLabel) => {
      const options = [
        createConditionOption('', emptyLabel, selectedValue.length === 0),
        ...ruleValueLists
          .filter((valueList) => valueList.kind === kind)
          .map((valueList) => {
            const label =
              typeof valueList.label === 'string' && valueList.label.length > 0
                ? valueList.label
                : valueList.id;
            return createConditionOption(
              valueList.id,
              label +
                ' · ' +
                String(Array.isArray(valueList.values) ? valueList.values.length : 0) +
                ' values',
              valueList.id === selectedValue,
            );
          }),
      ];

      return createConditionField(
        labelText,
        createConditionSelect({ 'data-field': fieldName }, options),
        false,
      );
    };

    const renderConditionFields = (card, seed) => {
      const typeSelect = card.querySelector('.ct-admin__condition-type');
      const fieldsContainer = card.querySelector('.ct-admin__condition-fields');

      if (!(typeSelect instanceof HTMLSelectElement) || !(fieldsContainer instanceof HTMLElement)) {
        return;
      }

      const conditionType = typeSelect.value;
      updateConditionCardClass(card, conditionType);
      const coursePlaceholder = getCoursePlaceholder();
      const programCoursePlaceholder = deriveRelatedCourseIds(coursePlaceholder, 3).join(', ');
      const surveyPlaceholder = coursePlaceholder + '_EXIT_SURVEY';

      if (conditionType === 'course_completion') {
        const selectedCourseId = typeof seed.courseId === 'string' ? seed.courseId : '';
        replaceConditionFields(fieldsContainer, [
          createCourseSearchField('courseId'),
          createCourseSelectField('Course', 'courseId', selectedCourseId, false),
          createConditionField(
            'Minimum completion % (optional)',
            createConditionInput('number', {
              'data-field': 'minCompletionPercent',
              min: '0',
              max: '100',
              step: '0.01',
            }),
          ),
          createConditionCheckbox('requireCompleted', 'Course must be completed', true),
        ]);

        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'minCompletionPercent',
          typeof seed.minCompletionPercent === 'number' ? String(seed.minCompletionPercent) : '',
        );
        setCheckboxOnCard(
          card,
          'requireCompleted',
          seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
        );
        bindExclusiveFieldPair(card, 'courseId', 'courseListId');
        bindSearchableCourseSelect(card, 'courseId');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'grade_threshold') {
        const selectedCourseId = typeof seed.courseId === 'string' ? seed.courseId : '';
        replaceConditionFields(fieldsContainer, [
          createCourseSearchField('courseId'),
          createCourseSelectField('Course', 'courseId', selectedCourseId, false),
          createConditionField(
            'Score field',
            createConditionSelect({ 'data-field': 'scoreField' }, [
              createConditionOption('final_score', 'Final score', false),
              createConditionOption('current_score', 'Current score', false),
            ]),
          ),
          createConditionField(
            'Minimum score (optional)',
            createConditionInput('number', {
              'data-field': 'minScore',
              min: '0',
              max: '100',
              step: '0.01',
            }),
          ),
          createConditionField(
            'Maximum score (optional)',
            createConditionInput('number', {
              'data-field': 'maxScore',
              min: '0',
              max: '100',
              step: '0.01',
            }),
          ),
        ]);

        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'scoreField',
          seed.scoreField === 'current_score' ? 'current_score' : 'final_score',
        );
        setFieldOnCard(card, 'minScore', typeof seed.minScore === 'number' ? String(seed.minScore) : '');
        setFieldOnCard(card, 'maxScore', typeof seed.maxScore === 'number' ? String(seed.maxScore) : '');
        bindExclusiveFieldPair(card, 'courseId', 'courseListId');
        bindSearchableCourseSelect(card, 'courseId');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'program_completion') {
        const selectedCourseIds = Array.isArray(seed.courseIds) ? seed.courseIds.join(',') : '';
        replaceConditionFields(fieldsContainer, [
          createCourseSearchField('courseIds'),
          createCourseSelectField('Courses', 'courseIds', selectedCourseIds, true),
          createConditionField(
            'Minimum completed (optional)',
            createConditionInput('number', {
              'data-field': 'minimumCompleted',
              min: '1',
              max: '200',
              step: '1',
            }),
          ),
        ]);

        setFieldOnCard(
          card,
          'courseListId',
          typeof seed.courseListId === 'string' ? seed.courseListId : '',
        );
        setFieldOnCard(
          card,
          'minimumCompleted',
          typeof seed.minimumCompleted === 'number' ? String(seed.minimumCompleted) : '',
        );
        bindExclusiveFieldPair(card, 'courseIds', 'courseListId');
        bindSearchableCourseSelect(card, 'courseIds');
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'assignment_submission') {
        const selectedCourseId = typeof seed.courseId === 'string' ? seed.courseId : '';
        const selectedAssignmentId =
          typeof seed.assignmentId === 'string' ? seed.assignmentId : '';
        const selectedWorkflowStates = Array.isArray(seed.workflowStates)
          ? seed.workflowStates.join(',')
          : '';
        replaceConditionFields(fieldsContainer, [
          createCourseSearchField('courseId'),
          createCourseSelectField('Course', 'courseId', selectedCourseId, false),
          createConditionField(
            'Gradebook item search',
            createConditionInput('search', {
              'data-lms-gradebook-item-query': true,
              placeholder: 'Search by title or ID',
            }),
          ),
          createConditionField(
            'Gradebook item',
            createConditionSelect(
              {
                'data-field': 'assignmentId',
                'data-lms-gradebook-item-select': true,
                'data-selected-value': selectedAssignmentId,
                required: true,
              },
              [createConditionOption('', 'Select course first', false)],
            ),
          ),
          createConditionField(
            'Minimum score (optional)',
            createConditionInput('number', {
              'data-field': 'minScore',
              min: '0',
              max: '100',
              step: '0.01',
            }),
          ),
          createConditionField(
            'Workflow states',
            createConditionSelect(
              {
                'data-field': 'workflowStates',
                'data-lms-workflow-state-select': true,
                'data-selected-values': selectedWorkflowStates,
                multiple: true,
                size: '5',
              },
              [createConditionOption('', 'Select gradebook item first', false)],
            ),
          ),
          createConditionCheckbox(
            'requireSubmitted',
            'Gradebook item must be submitted',
            true,
          ),
        ]);

        setFieldOnCard(card, 'minScore', typeof seed.minScore === 'number' ? String(seed.minScore) : '');
        setCheckboxOnCard(
          card,
          'requireSubmitted',
          seed.requireSubmitted === undefined ? true : Boolean(seed.requireSubmitted),
        );
        bindSearchableCourseSelect(card, 'courseId');
        bindSearchableGradebookItemSelect(card);
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'survey_completion') {
        replaceConditionFields(fieldsContainer, [
          createConditionField(
            'Survey ID',
            createConditionInput('text', {
              'data-field': 'surveyId',
              placeholder: surveyPlaceholder,
            }),
          ),
          createConditionField(
            'Source (optional)',
            createConditionInput('text', {
              'data-field': 'source',
              placeholder: 'qualtrics',
            }),
          ),
          createConditionCheckbox('requireCompleted', 'Survey must be completed', true),
        ]);

        setFieldOnCard(
          card,
          'surveyId',
          typeof seed.surveyId === 'string' ? seed.surveyId : '',
        );
        setFieldOnCard(card, 'source', typeof seed.source === 'string' ? seed.source : '');
        setCheckboxOnCard(
          card,
          'requireCompleted',
          seed.requireCompleted === undefined ? true : Boolean(seed.requireCompleted),
        );
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'time_window') {
        replaceConditionFields(fieldsContainer, [
          createConditionField(
            'Not before (optional)',
            createConditionInput('datetime-local', { 'data-field': 'notBefore' }),
            false,
          ),
          createConditionField(
            'Not after (optional)',
            createConditionInput('datetime-local', { 'data-field': 'notAfter' }),
            false,
          ),
        ]);

        setFieldOnCard(card, 'notBefore', toDateTimeLocalInput(seed.notBefore));
        setFieldOnCard(card, 'notAfter', toDateTimeLocalInput(seed.notAfter));
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'custom_field') {
        const valueType =
          typeof seed.expectedValue === 'number'
            ? 'number'
            : typeof seed.expectedValue === 'boolean'
              ? 'boolean'
              : 'string';
        replaceConditionFields(fieldsContainer, [
          createConditionField(
            'Field name',
            createConditionInput('text', {
              'data-field': 'fieldName',
              placeholder: 'programStanding',
            }),
            false,
          ),
          createConditionField(
            'Operator',
            createConditionSelect({ 'data-field': 'operator' }, [
              createConditionOption('equals', 'Equals', false),
              createConditionOption('not_equals', 'Does not equal', false),
              createConditionOption('contains', 'Contains', false),
              createConditionOption('greater_than_or_equal', 'Greater than or equal', false),
              createConditionOption('less_than_or_equal', 'Less than or equal', false),
            ]),
            false,
          ),
          createConditionField(
            'Value type',
            createConditionSelect({ 'data-field': 'expectedValueType' }, [
              createConditionOption('string', 'Text', false),
              createConditionOption('number', 'Number', false),
              createConditionOption('boolean', 'True/false', false),
            ]),
            false,
          ),
          createConditionField(
            'Expected value',
            createConditionInput('text', {
              'data-field': 'expectedValue',
              placeholder: 'eligible',
            }),
            false,
          ),
        ]);

        setFieldOnCard(
          card,
          'fieldName',
          typeof seed.fieldName === 'string' ? seed.fieldName : '',
        );
        setFieldOnCard(
          card,
          'operator',
          typeof seed.operator === 'string' ? seed.operator : 'equals',
        );
        setFieldOnCard(card, 'expectedValueType', valueType);
        setFieldOnCard(
          card,
          'expectedValue',
          seed.expectedValue === undefined ? '' : String(seed.expectedValue),
        );
        updateConditionPlainSummary(card);
        return;
      }

      replaceConditionFields(fieldsContainer, [
        createConditionField(
          'Required badge template ID',
          createConditionInput('text', {
            'data-field': 'badgeTemplateId',
            placeholder: 'badge_template_foundations',
          }),
          false,
        ),
        createListSelectField(
          'Reusable badge-template list',
          'badgeTemplateListId',
          'badge_template_ids',
          typeof seed.badgeTemplateListId === 'string' ? seed.badgeTemplateListId : '',
          'Use single badge template',
        ),
      ]);
      setFieldOnCard(
        card,
        'badgeTemplateId',
        typeof seed.badgeTemplateId === 'string' ? seed.badgeTemplateId : '',
      );
      setFieldOnCard(
        card,
        'badgeTemplateListId',
        typeof seed.badgeTemplateListId === 'string' ? seed.badgeTemplateListId : '',
      );
      bindExclusiveFieldPair(card, 'badgeTemplateId', 'badgeTemplateListId');
      updateConditionPlainSummary(card);
    };
`;
