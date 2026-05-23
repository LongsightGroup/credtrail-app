export const INSTITUTION_ADMIN_RULE_BUILDER_CONDITION_FIELDS_JS = `
    const getConditionCards = () => {
      return Array.from(
        ruleBuilderConditionList.querySelectorAll('.ct-admin__condition-card'),
      ).filter((candidate) => candidate instanceof HTMLElement);
    };

    const readFieldFromCard = (card, fieldName) => {
      const field = card.querySelector('[data-field="' + fieldName + '"]');

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
          'Learner submits ' +
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
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use single course ID') +
          '</select></label>' +
          '<label>Min completion % (optional)<input type="number" data-field="minCompletionPercent" min="0" max="100" step="0.01" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireCompleted" checked />Require completed</label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
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
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'grade_threshold') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use single course ID') +
          '</select></label>' +
          '<label>Score field<select data-field="scoreField"><option value="final_score">Final score</option><option value="current_score">Current score</option></select></label>' +
          '<label>Min score (optional)<input type="number" data-field="minScore" min="0" max="100" step="0.01" /></label>' +
          '<label>Max score (optional)<input type="number" data-field="maxScore" min="0" max="100" step="0.01" /></label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
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
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'program_completion') {
        fieldsContainer.innerHTML =
          '<label>Course IDs (comma separated)<input type="text" data-field="courseIds" placeholder="' +
          programCoursePlaceholder +
          '" /></label>' +
          '<label>Reusable course list<select data-field="courseListId">' +
          listOptionsMarkup('course_ids', typeof seed.courseListId === 'string' ? seed.courseListId : '', 'Use explicit course IDs') +
          '</select></label>' +
          '<label>Minimum completed (optional)<input type="number" data-field="minimumCompleted" min="1" max="200" step="1" /></label>';

        setFieldOnCard(
          card,
          'courseIds',
          Array.isArray(seed.courseIds) ? seed.courseIds.join(', ') : '',
        );
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
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'assignment_submission') {
        fieldsContainer.innerHTML =
          '<label>Course ID<input type="text" data-field="courseId" placeholder="' +
          coursePlaceholder +
          '" /></label>' +
          '<label>Assignment ID<input type="text" data-field="assignmentId" placeholder="assignment_1" /></label>' +
          '<label>Min score (optional)<input type="number" data-field="minScore" min="0" max="100" step="0.01" /></label>' +
          '<label>Workflow states (comma separated, optional)<input type="text" data-field="workflowStates" placeholder="submitted,graded" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireSubmitted" checked />Require submitted</label>';

        setFieldOnCard(card, 'courseId', typeof seed.courseId === 'string' ? seed.courseId : '');
        setFieldOnCard(
          card,
          'assignmentId',
          typeof seed.assignmentId === 'string' ? seed.assignmentId : '',
        );
        setFieldOnCard(card, 'minScore', typeof seed.minScore === 'number' ? String(seed.minScore) : '');
        setFieldOnCard(
          card,
          'workflowStates',
          Array.isArray(seed.workflowStates) ? seed.workflowStates.join(', ') : '',
        );
        setCheckboxOnCard(
          card,
          'requireSubmitted',
          seed.requireSubmitted === undefined ? true : Boolean(seed.requireSubmitted),
        );
        updateConditionPlainSummary(card);
        return;
      }

      if (conditionType === 'survey_completion') {
        fieldsContainer.innerHTML =
          '<label>Survey ID<input type="text" data-field="surveyId" placeholder="' +
          surveyPlaceholder +
          '" /></label>' +
          '<label>Source (optional)<input type="text" data-field="source" placeholder="qualtrics" /></label>' +
          '<label class="ct-admin__checkbox-row ct-checkbox-row"><input type="checkbox" data-field="requireCompleted" checked />Require completed</label>';

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
        fieldsContainer.innerHTML =
          '<label>Not before (optional)<input type="datetime-local" data-field="notBefore" /></label>' +
          '<label>Not after (optional)<input type="datetime-local" data-field="notAfter" /></label>';

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
        fieldsContainer.innerHTML =
          '<label>Field name<input type="text" data-field="fieldName" placeholder="programStanding" /></label>' +
          '<label>Operator<select data-field="operator"><option value="equals">Equals</option><option value="not_equals">Does not equal</option><option value="contains">Contains</option><option value="greater_than_or_equal">Greater than or equal</option><option value="less_than_or_equal">Less than or equal</option></select></label>' +
          '<label>Value type<select data-field="expectedValueType"><option value="string">Text</option><option value="number">Number</option><option value="boolean">True/false</option></select></label>' +
          '<label>Expected value<input type="text" data-field="expectedValue" placeholder="eligible" /></label>';

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

      fieldsContainer.innerHTML =
        '<label>Required badge template ID<input type="text" data-field="badgeTemplateId" placeholder="badge_template_foundations" /></label>' +
        '<label>Reusable badge-template list<select data-field="badgeTemplateListId">' +
        listOptionsMarkup(
          'badge_template_ids',
          typeof seed.badgeTemplateListId === 'string' ? seed.badgeTemplateListId : '',
          'Use single badge template',
        ) +
        '</select></label>';
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
