export const INSTITUTION_ADMIN_RULE_BUILDER_SUMMARY_JS = `
    let ruleBuilderLastTestSummary = 'Not run';

    const resetConditionEvaluationResults = () => {
      getConditionCards().forEach((card) => {
        setConditionResultState(card, 'idle', 'Not evaluated yet.');
      });
    };

    const collectLeafEvaluationNodes = (node, output) => {
      if (node === null || typeof node !== 'object') {
        return;
      }

      const children = Array.isArray(node.children) ? node.children : [];

      if (children.length === 0) {
        output.push(node);
        return;
      }

      children.forEach((child) => {
        collectLeafEvaluationNodes(child, output);
      });
    };

    const rootChildrenFromEvaluationTree = (tree) => {
      if (tree === null || typeof tree !== 'object') {
        return [];
      }

      return Array.isArray(tree.children) ? tree.children : [];
    };

    const applyConditionEvaluationResults = (evaluation) => {
      const cards = getConditionCards();

      if (cards.length === 0) {
        return {
          total: 0,
          matched: 0,
        };
      }

      const directChildren = rootChildrenFromEvaluationTree(
        evaluation && typeof evaluation === 'object' ? evaluation.tree : null,
      );
      let mappedNodes = directChildren;

      if (mappedNodes.length !== cards.length) {
        const leafNodes = [];
        collectLeafEvaluationNodes(
          evaluation && typeof evaluation === 'object' ? evaluation.tree : null,
          leafNodes,
        );
        mappedNodes = leafNodes.length === cards.length ? leafNodes : [];
      }

      if (mappedNodes.length !== cards.length) {
        resetConditionEvaluationResults();
        return {
          total: cards.length,
          matched: 0,
        };
      }

      let matchedCount = 0;

      cards.forEach((card, index) => {
        const node = mappedNodes[index];
        const matched = node && typeof node.matched === 'boolean' ? node.matched : null;
        const detail = node && typeof node.detail === 'string' ? node.detail : 'No evaluation detail.';
        const resultKind =
          node && typeof node.resultKind === 'string' ? node.resultKind : null;

        if (matched === true) {
          matchedCount += 1;
          setConditionResultState(card, 'pass', 'Pass: ' + detail);
          return;
        }

        if (resultKind === 'missing_data') {
          setConditionResultState(card, 'review', 'Missing data: ' + detail);
          return;
        }

        if (matched === false) {
          setConditionResultState(card, 'fail', 'Fail: ' + detail);
          return;
        }

        setConditionResultState(card, 'idle', 'Not evaluated.');
      });

      return {
        total: cards.length,
        matched: matchedCount,
      };
    };

    const setSummaryText = (element, value) => {
      if (element instanceof HTMLElement) {
        element.textContent = value;
      }
    };

    const setSummaryTone = (element, tone) => {
      if (!(element instanceof HTMLElement)) {
        return;
      }

      if (typeof tone !== 'string' || tone.length === 0) {
        delete element.dataset.tone;
        return;
      }

      element.dataset.tone = tone;
    };

    const syncConditionCanvasMeta = () => {
      const cards = getConditionCards();

      cards.forEach((card, index) => {
        const indexElement = card.querySelector('[data-condition-index]');

        if (indexElement instanceof HTMLElement) {
          indexElement.textContent = 'Requirement ' + String(index + 1);
        }

        const moveUpButton = card.querySelector('button[data-condition-move="up"]');
        const moveDownButton = card.querySelector('button[data-condition-move="down"]');

        if (moveUpButton instanceof HTMLButtonElement) {
          moveUpButton.disabled = index === 0;
        }

        if (moveDownButton instanceof HTMLButtonElement) {
          moveDownButton.disabled = index === cards.length - 1;
        }
      });

      if (ruleBuilderConditionEmpty instanceof HTMLElement) {
        ruleBuilderConditionEmpty.hidden = cards.length > 0;
      }

      if (ruleBuilderCanvasCount instanceof HTMLElement) {
        ruleBuilderCanvasCount.textContent =
          String(cards.length) + (cards.length === 1 ? ' requirement' : ' requirements');
      }

      if (ruleBuilderCanvasLogic instanceof HTMLElement) {
        const rootLogic = getRuleBuilderRootLogic();
        ruleBuilderCanvasLogic.textContent =
          rootLogic === 'any'
            ? 'Learner can meet any one requirement'
            : 'Learner must meet every requirement';
        ruleBuilderCanvasLogic.className = adminStatusPillClass(
          rootLogic === 'any' ? 'warning' : 'active',
        );
      }

      syncRootLogicToolbarVisibility();
    };

    const syncRootLogicToolbarVisibility = () => {
      const rootLogic = getRuleBuilderRootLogic();

      if (ruleBuilderAddAlternativePathButton instanceof HTMLButtonElement) {
        ruleBuilderAddAlternativePathButton.hidden = rootLogic === 'any';
      }

      if (ruleBuilderRequireEveryRequirementButton instanceof HTMLButtonElement) {
        ruleBuilderRequireEveryRequirementButton.hidden = rootLogic === 'all';
      }
    };

    const syncRuleBuilderStepCompletion = () => {
      const completion = getRuleBuilderCompletionState();

      ruleBuilderStepButtons.forEach((candidate) => {
        if (!(candidate instanceof HTMLButtonElement)) {
          return;
        }

        const targetStep = candidate.dataset.ruleStepTarget ?? '';
        const isDone = completion[targetStep] === true;
        candidate.classList.toggle('is-done', isDone);
      });

      const completedCount = Object.values(completion).filter((value) => value).length;
      const activeStep = ruleBuilderStepOrder[activeRuleBuilderStepIndex] ?? '';
      const activeStepLabel = ruleBuilderStepLabels[activeStep] ?? 'Step';

      if (ruleBuilderStepProgress instanceof HTMLElement) {
        ruleBuilderStepProgress.textContent =
          'Step ' +
          String(activeRuleBuilderStepIndex + 1) +
          ' of ' +
          String(ruleBuilderStepOrder.length) +
          ' · ' +
          activeStepLabel +
          ' · ' +
          String(completedCount) +
          '/' +
          String(ruleBuilderStepOrder.length) +
          ' complete';
      }

      updateStepNavigationState();
    };

    const syncRuleBuilderSummary = (statusOverride) => {
      renderRuleFlowPreview();
      renderSourceReadiness();

      const ruleName = getTextFieldValue('name');
      const cardCount = getConditionCards().length;
      const rootLogicLabel =
        getRuleBuilderRootLogic() === 'any'
          ? 'Learner can meet any one requirement'
          : 'Learner must meet every requirement';
      let definitionStatus = 'Drafting';
      let definitionTone = 'warning';
      let summaryMessage = 'Add at least one requirement to create a draft.';

      if (cardCount === 0) {
        definitionStatus = 'Needs requirements';
        definitionTone = 'warning';
      } else {
        const validationErrors = validateConditionCards(false);

        if (validationErrors.length > 0) {
          definitionStatus = 'Needs attention';
          definitionTone = 'error';
          summaryMessage = validationErrors[0];
        } else {
          try {
            const definition = readDefinitionFromBuilder(true);
            const rootConditions =
              definition &&
              typeof definition === 'object' &&
              definition.conditions &&
              typeof definition.conditions === 'object'
                ? definition.conditions
                : null;
            const childCount =
              rootConditions !== null && Array.isArray(rootConditions.all)
                ? rootConditions.all.length
                : rootConditions !== null && Array.isArray(rootConditions.any)
                  ? rootConditions.any.length
                  : cardCount;

            definitionStatus = childCount > 0 ? 'Ready for review' : 'Needs requirements';
            definitionTone = childCount > 0 ? 'success' : 'warning';
            summaryMessage =
              childCount > 0
                ? 'Requirements are synchronized with the generated rule JSON.'
                : 'Add one or more requirements to continue.';
          } catch (error) {
            definitionStatus = 'Needs attention';
            definitionTone = 'error';
            summaryMessage =
              error instanceof Error ? error.message : 'Definition is not ready for submission.';
          }
        }
      }

      let lastTestTone = 'info';

      if (ruleBuilderLastTestSummary.startsWith('Matched')) {
        lastTestTone = 'success';
      } else if (ruleBuilderLastTestSummary.startsWith('Review required')) {
        lastTestTone = 'warning';
      } else if (ruleBuilderLastTestSummary.startsWith('No match')) {
        lastTestTone = 'warning';
      } else if (
        ruleBuilderLastTestSummary.startsWith('Failed') ||
        ruleBuilderLastTestSummary.includes('invalid') ||
        ruleBuilderLastTestSummary.includes('Missing')
      ) {
        lastTestTone = 'error';
      }

      setSummaryText(
        ruleBuilderSummaryRuleName,
        ruleName.length > 0 ? ruleName : '(unnamed draft)',
      );
      setSummaryText(ruleBuilderSummaryConditionCount, String(cardCount));
      setSummaryText(ruleBuilderSummaryRootLogic, rootLogicLabel);
      setSummaryText(ruleBuilderSummaryValidity, definitionStatus);
      setSummaryText(ruleBuilderSummaryLastTest, ruleBuilderLastTestSummary);
      setSummaryText(ruleBuilderSummaryMessage, statusOverride ?? summaryMessage);
      setSummaryTone(ruleBuilderSummaryValidity, definitionTone);
      setSummaryTone(ruleBuilderSummaryLastTest, lastTestTone);
      setSummaryTone(
        ruleBuilderSummaryMessage,
        statusOverride === undefined
          ? definitionTone
          : ruleCreateStatus.dataset.tone === 'error'
            ? 'error'
            : ruleCreateStatus.dataset.tone === 'success'
              ? 'success'
              : ruleCreateStatus.dataset.tone === 'warning'
                ? 'warning'
                : 'info',
      );
      syncRuleBuilderStepCompletion();
    };

    const syncDefinitionJsonFromBuilder = () => {
      syncConditionCanvasMeta();
      renderRuleFlowPreview();
      renderSourceReadiness();

      try {
        const definition = readDefinitionFromBuilder(false);
        ruleBuilderDefinitionJson.value = JSON.stringify(definition, null, 2);
      } catch {
        // Ignore transient editing errors while user updates fields.
      }

      ruleBuilderLastTestSummary = 'Not run';
      validateConditionCards(true);
      getConditionCards().forEach((card) => {
        updateConditionPlainSummary(card);
      });
      syncRuleBuilderSummary();
    };

    const createConditionCard = (seed) => {
      const card = cloneRuleBuilderConditionCard();

      if (!(card instanceof HTMLElement)) {
        return null;
      }

      const typeSelect = card.querySelector('.ct-admin__condition-type');

      if (typeSelect instanceof HTMLSelectElement) {
        typeSelect.value = typeof seed.type === 'string' ? seed.type : 'grade_threshold';
      }

      setCheckboxOnCard(card, 'negate', Boolean(seed.negate));
      renderConditionFields(card, seed);
      setConditionResultState(card, 'idle', 'Not evaluated yet.');

      card.addEventListener('change', (event) => {
        const target = event.target;

        if (target instanceof HTMLSelectElement && target.classList.contains('ct-admin__condition-type')) {
          renderConditionFields(card, {
            type: target.value,
            negate: readCheckboxFromCard(card, 'negate'),
          });
        }

        syncDefinitionJsonFromBuilder();
      });

      card.addEventListener('input', () => {
        syncDefinitionJsonFromBuilder();
      });

      card.addEventListener('click', (event) => {
        const target = event.target;

        if (target instanceof HTMLButtonElement && target.dataset.conditionMove === 'up') {
          const previous = card.previousElementSibling;

          if (previous instanceof HTMLElement) {
            ruleBuilderConditionList.insertBefore(card, previous);
          }

          syncDefinitionJsonFromBuilder();
          return;
        }

        if (target instanceof HTMLButtonElement && target.dataset.conditionMove === 'down') {
          const next = card.nextElementSibling;

          if (next instanceof HTMLElement) {
            ruleBuilderConditionList.insertBefore(next, card);
          }

          syncDefinitionJsonFromBuilder();
          return;
        }

        if (target instanceof HTMLButtonElement && target.classList.contains('ct-admin__condition-remove')) {
          card.remove();
          syncDefinitionJsonFromBuilder();
        }
      });

      card.addEventListener('dragstart', () => {
        card.classList.add('is-dragging');
      });

      card.addEventListener('dragend', () => {
        card.classList.remove('is-dragging');
        syncDefinitionJsonFromBuilder();
      });

      return card;
    };

    const getDragAfterElement = (container, y) => {
      const cards = Array.from(
        container.querySelectorAll('.ct-admin__condition-card:not(.is-dragging)'),
      );
      let closestOffset = Number.NEGATIVE_INFINITY;
      let closestElement = null;

      cards.forEach((card) => {
        if (!(card instanceof HTMLElement)) {
          return;
        }

        const box = card.getBoundingClientRect();
        const offset = y - box.top - box.height / 2;

        if (offset < 0 && offset > closestOffset) {
          closestOffset = offset;
          closestElement = card;
        }
      });

      return closestElement;
    };

    ruleBuilderConditionList.addEventListener('dragover', (event) => {
      event.preventDefault();
      const dragging = ruleBuilderConditionList.querySelector('.ct-admin__condition-card.is-dragging');

      if (!(dragging instanceof HTMLElement)) {
        return;
      }

      const afterElement = getDragAfterElement(ruleBuilderConditionList, event.clientY);

      if (afterElement === null) {
        ruleBuilderConditionList.appendChild(dragging);
        return;
      }

      ruleBuilderConditionList.insertBefore(dragging, afterElement);
    });

    const clearConditionCanvas = () => {
      ruleBuilderConditionList.innerHTML = '';
    };

    const addConditionToCanvas = (seed) => {
      const card = createConditionCard(seed);

      if (!(card instanceof HTMLElement)) {
        setStatus(ruleCreateStatus, 'Unable to add requirement row.', true);
        return;
      }

      ruleBuilderConditionList.appendChild(card);
      syncDefinitionJsonFromBuilder();
    };

    const refreshConditionCardValueListOptions = () => {
      getConditionCards().forEach((card) => {
        try {
          const currentCondition = readConditionFromCard(card, false);
          const normalizedCondition = normalizeLeafConditionForBuilder(currentCondition);

          if (normalizedCondition === null) {
            return;
          }

          const typeSelect = card.querySelector('.ct-admin__condition-type');

          if (typeSelect instanceof HTMLSelectElement) {
            typeSelect.value = normalizedCondition.type;
          }

          setCheckboxOnCard(card, 'negate', Boolean(normalizedCondition.negate));
          renderConditionFields(card, normalizedCondition);
        } catch {
          // Ignore partially edited cards while refreshing reusable-list options.
        }
      });
    };

    const normalizeLeafConditionForBuilder = (condition) => {
      if (condition === null || typeof condition !== 'object' || Array.isArray(condition)) {
        return null;
      }

      if ('type' in condition && typeof condition.type === 'string') {
        return {
          ...condition,
          negate: false,
        };
      }

      if ('not' in condition) {
        const nested = normalizeLeafConditionForBuilder(condition.not);

        if (nested === null) {
          return null;
        }

        return {
          ...nested,
          negate: true,
        };
      }

      return null;
    };

    const applyDefinitionToBuilder = (definition, sourceLabel) => {
      if (definition === null || typeof definition !== 'object' || !('conditions' in definition)) {
        throw new Error('Rule definition must include a conditions object.');
      }

      const reviewOnMissingFacts =
        definition.options &&
        typeof definition.options === 'object' &&
        definition.options.reviewOnMissingFacts === true;
      const reviewOnMissingFactsField = getRuleCreateField('reviewOnMissingFacts');

      if (reviewOnMissingFactsField instanceof HTMLInputElement) {
        reviewOnMissingFactsField.checked = reviewOnMissingFacts;
      }

      const rootConditions = definition.conditions;
      let rootLogic = 'all';
      let rawChildren = [];

      if (rootConditions && typeof rootConditions === 'object' && Array.isArray(rootConditions.all)) {
        rootLogic = 'all';
        rawChildren = rootConditions.all;
      } else if (rootConditions && typeof rootConditions === 'object' && Array.isArray(rootConditions.any)) {
        rootLogic = 'any';
        rawChildren = rootConditions.any;
      } else {
        rawChildren = [rootConditions];
      }

      const normalizedChildren = rawChildren
        .map((condition) => normalizeLeafConditionForBuilder(condition))
        .filter((condition) => condition !== null);

      if (normalizedChildren.length !== rawChildren.length) {
        setStatus(
          ruleCreateStatus,
          sourceLabel +
            ' includes nested requirement groups not editable as rows. JSON mode remains active.',
          true,
        );
        syncRuleBuilderSummary(
          sourceLabel +
            ' includes nested requirement groups not editable as rows. Adjust JSON manually.',
        );
        return;
      }

      clearConditionCanvas();
      setRuleBuilderRootLogic(rootLogic);
      normalizedChildren.forEach((seed) => {
        addConditionToCanvas(seed);
      });

      if (normalizedChildren.length === 0) {
        addConditionToCanvas({
          type: 'course_completion',
          courseId: getDefaultCourseId() || getCoursePlaceholder(),
          requireCompleted: true,
          negate: false,
        });
      }

      syncDefinitionJsonFromBuilder();
      setStatus(ruleCreateStatus, sourceLabel + ' loaded into visual builder.', false, 'success');
      syncRuleBuilderSummary(sourceLabel + ' loaded into visual builder.');
    };

    const parseDefinitionJson = () => {
      const definitionJsonText = ruleBuilderDefinitionJson.value.trim();
      const fallbackDefinition = readDefinitionFromBuilder(true);

      if (definitionJsonText.length === 0) {
        return fallbackDefinition;
      }

      let parsed;

      try {
        parsed = JSON.parse(definitionJsonText);
      } catch {
        throw new Error('Rule JSON is not valid JSON.');
      }

      if (parsed === null || typeof parsed !== 'object' || !('conditions' in parsed)) {
        throw new Error('Rule JSON must include a top-level conditions object.');
      }

      return parsed;
    };
`;
