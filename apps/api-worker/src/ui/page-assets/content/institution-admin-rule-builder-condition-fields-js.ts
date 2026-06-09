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
        const completionPercent =
          typeof condition.minCompletionPercent === 'number'
            ? condition.minCompletionPercent
            : 100;

        return (
          'Learner has completed at least ' +
          String(completionPercent) +
          '% of gradebook items in ' +
          courseLabel
        );
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

`;
