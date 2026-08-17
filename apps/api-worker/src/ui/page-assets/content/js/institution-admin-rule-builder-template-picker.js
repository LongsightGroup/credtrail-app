const normalizeSearchQuery = (query) => query.trim().normalize("NFKC").toLocaleLowerCase();

const optionTitle = (option) => option.dataset.templateTitle?.trim() ?? "";

const optionSearchText = (option) =>
  (option.dataset.templateSearchText ?? optionTitle(option)).normalize("NFKC").toLocaleLowerCase();

const selectableTemplateOptions = (select) =>
  select instanceof HTMLSelectElement
    ? Array.from(select.options).filter(
        (option) => option.value.trim().length > 0 && !option.disabled,
      )
    : [];

const selectedTemplateOption = (select) => {
  if (!(select instanceof HTMLSelectElement)) {
    return null;
  }

  const option = select.selectedOptions[0];
  return option instanceof HTMLOptionElement && option.value.trim().length > 0 ? option : null;
};

const filterTemplateRows = (optionRows, query) => {
  const normalizedQuery = normalizeSearchQuery(query);

  return optionRows.filter(({ option, row }) => {
    const isVisible =
      normalizedQuery.length === 0 || optionSearchText(option).includes(normalizedQuery);
    row.hidden = !isVisible;
    return isVisible;
  });
};

const buildTemplateOptionRow = (option, index, commitOption) => {
  const row = document.createElement("div");
  row.id = "rule-builder-badge-template-option-" + String(index + 1);
  row.className = "ct-admin__template-option";
  row.setAttribute("role", "option");
  row.setAttribute("aria-selected", "false");
  row.dataset.templateValue = option.value;

  const title = document.createElement("span");
  title.className = "ct-admin__template-option-title";
  title.textContent = optionTitle(option);
  row.append(title);

  const usageCount = Number.parseInt(option.dataset.ruleUsageCount ?? "0", 10);
  if (Number.isFinite(usageCount) && usageCount > 0) {
    const usage = document.createElement("span");
    usage.className = "ct-admin__template-option-meta";
    usage.textContent =
      "Used by " + String(usageCount) + (usageCount === 1 ? " other rule" : " other rules");
    row.append(usage);
  }

  row.addEventListener("pointerdown", (event) => event.preventDefault());
  row.addEventListener("click", () => {
    commitOption(option);
  });
  return { option, row };
};

const createTemplateReuseState = (input) => {
  const { select, reusePanel, reuseMessage, reuseConfirmation, onStateChange } = input;

  const syncReuse = (resetConfirmation = false) => {
    if (
      !(reusePanel instanceof HTMLElement) ||
      !(reuseMessage instanceof HTMLElement) ||
      !(reuseConfirmation instanceof HTMLInputElement)
    ) {
      return;
    }

    if (resetConfirmation) {
      reuseConfirmation.checked = false;
    }

    const option = selectedTemplateOption(select);
    const usageCount = Number.parseInt(option?.dataset.ruleUsageCount ?? "0", 10);

    if (option === null || !Number.isFinite(usageCount) || usageCount < 1) {
      reusePanel.hidden = true;
      reuseMessage.textContent = "";
      reuseConfirmation.required = false;
      reuseConfirmation.checked = false;
      return;
    }

    const usageNames = option.dataset.ruleUsageNames?.trim() ?? "";
    const ruleLabel = usageCount === 1 ? "other awarding rule" : "other awarding rules";
    const usageDetail = usageNames.length === 0 ? "" : " (" + usageNames + ")";
    reuseMessage.textContent =
      "This badge is already used by " +
      String(usageCount) +
      " " +
      ruleLabel +
      usageDetail +
      ". Reuse it only when this rule is another valid way to earn the same achievement. " +
      "Each rule keeps its own approval and issuance history.";
    reusePanel.hidden = false;
    reuseConfirmation.required = true;
  };

  const isComplete = () =>
    !(
      reuseConfirmation instanceof HTMLInputElement &&
      reuseConfirmation.required &&
      !reuseConfirmation.checked
    );

  const isReuseAcknowledged = () =>
    reuseConfirmation instanceof HTMLInputElement &&
    reuseConfirmation.required &&
    reuseConfirmation.checked;

  const wireReuseListeners = () => {
    if (reuseConfirmation instanceof HTMLInputElement) {
      reuseConfirmation.addEventListener("change", () => {
        if (typeof onStateChange === "function") {
          onStateChange();
        }
      });
    }
  };

  return { syncReuse, isComplete, isReuseAcknowledged, wireReuseListeners };
};

const createFallbackBadgeTemplatePickerController = (input) => {
  const { select, onStateChange } = input;
  const reuse = createTemplateReuseState(input);

  const sync = (resetConfirmation = false) => {
    reuse.syncReuse(resetConfirmation);
  };

  if (select instanceof HTMLSelectElement) {
    select.addEventListener("change", () => {
      sync(true);
      if (typeof onStateChange === "function") {
        onStateChange();
      }
    });
  }

  reuse.wireReuseListeners();
  sync();

  return Object.freeze({
    sync,
    isComplete: reuse.isComplete,
    isReuseAcknowledged: reuse.isReuseAcknowledged,
  });
};

const createEnhancedBadgeTemplatePickerController = (input) => {
  const {
    fallbackField,
    enhancedField,
    comboboxInput,
    select,
    listbox,
    searchStatus,
    options,
    onStateChange,
  } = input;
  const reuse = createTemplateReuseState(input);
  const defaultStatusText = searchStatus.textContent ?? "";

  let optionRows = [];
  let filteredRows = [];
  let activeIndex = null;
  let isOpen = false;
  let announcementTimer = null;

  const cancelAnnouncement = () => {
    if (announcementTimer !== null) {
      clearTimeout(announcementTimer);
      announcementTimer = null;
    }
  };

  const announceResults = (visibleCount) => {
    cancelAnnouncement();
    announcementTimer = setTimeout(() => {
      searchStatus.textContent =
        visibleCount === 0
          ? "No badge templates match this search."
          : String(visibleCount) +
            (visibleCount === 1 ? " badge template shown." : " badge templates shown.");
      announcementTimer = null;
    }, 200);
  };

  const updateSelectionStatus = () => {
    const option = selectedTemplateOption(select);
    searchStatus.textContent =
      option === null ? defaultStatusText : optionTitle(option) + " selected.";
  };

  const syncValidity = () => {
    comboboxInput.setCustomValidity(
      selectedTemplateOption(select) === null ? "Choose a badge template from the list." : "",
    );
  };

  const syncSelectedRows = () => {
    const selected = selectedTemplateOption(select);
    optionRows.forEach(({ option, row }) => {
      const isSelected = selected !== null && option.value === selected.value;
      row.setAttribute("aria-selected", isSelected ? "true" : "false");
      row.classList.toggle("is-selected", isSelected);
    });
  };

  const clearActiveRow = () => {
    optionRows.forEach(({ row }) => row.classList.remove("is-active"));
    activeIndex = null;
    comboboxInput.removeAttribute("aria-activedescendant");
  };

  const setActiveRow = (index) => {
    clearActiveRow();

    const pair = filteredRows[index];
    if (pair === undefined) {
      return;
    }

    activeIndex = index;
    pair.row.classList.add("is-active");
    comboboxInput.setAttribute("aria-activedescendant", pair.row.id);
    pair.row.scrollIntoView({ block: "nearest" });
  };

  const applyFilter = (query) => {
    filteredRows = filterTemplateRows(optionRows, query);
    clearActiveRow();

    const emptyRow = listbox.querySelector("[data-empty-result]");
    if (emptyRow instanceof HTMLElement) {
      emptyRow.hidden = filteredRows.length > 0;
    }
    announceResults(filteredRows.length);
  };

  const hideListbox = ({ restoreQuery = true } = {}) => {
    cancelAnnouncement();
    clearActiveRow();
    listbox.hidden = true;
    comboboxInput.setAttribute("aria-expanded", "false");
    isOpen = false;

    if (restoreQuery) {
      const option = selectedTemplateOption(select);
      comboboxInput.value = option === null ? "" : optionTitle(option);
    }
  };

  const openList = (showAll = false) => {
    applyFilter(showAll ? "" : comboboxInput.value);
    listbox.hidden = false;
    comboboxInput.setAttribute("aria-expanded", "true");
    isOpen = true;
  };

  const dismissList = () => {
    hideListbox({ restoreQuery: true });
    updateSelectionStatus();
  };

  const sync = (resetConfirmation = false, { updateSelectionStatus: shouldUpdateStatus = false } = {}) => {
    hideListbox({ restoreQuery: true });
    syncSelectedRows();
    syncValidity();
    reuse.syncReuse(resetConfirmation);

    if (shouldUpdateStatus) {
      updateSelectionStatus();
    }
  };

  const commitOption = (option) => {
    if (!(option instanceof HTMLOptionElement)) {
      return;
    }

    select.value = option.value;
    select.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const moveActiveRow = (direction) => {
    if (filteredRows.length === 0) {
      return;
    }

    if (activeIndex === null) {
      setActiveRow(direction > 0 ? 0 : filteredRows.length - 1);
      return;
    }

    const nextIndex = (activeIndex + direction + filteredRows.length) % filteredRows.length;
    setActiveRow(nextIndex);
  };

  optionRows = options.map((option, index) =>
    buildTemplateOptionRow(option, index, (selectedOption) => {
      comboboxInput.focus();
      commitOption(selectedOption);
    }),
  );

  const emptyRow = document.createElement("div");
  emptyRow.className = "ct-admin__template-empty";
  emptyRow.dataset.emptyResult = "";
  emptyRow.textContent = "No badge templates match this search.";
  emptyRow.hidden = true;
  listbox.replaceChildren(...optionRows.map(({ row }) => row), emptyRow);

  select.required = false;
  comboboxInput.required = true;
  fallbackField.hidden = true;
  enhancedField.hidden = false;

  select.addEventListener("change", () => {
    sync(true, { updateSelectionStatus: true });
    if (typeof onStateChange === "function") {
      onStateChange();
    }
  });

  reuse.wireReuseListeners();

  comboboxInput.addEventListener("focus", () => openList(true));
  comboboxInput.addEventListener("click", () => openList(true));
  comboboxInput.addEventListener("input", () => openList());
  comboboxInput.addEventListener("blur", dismissList);
  comboboxInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!isOpen) {
        openList(true);
      }
      moveActiveRow(event.key === "ArrowDown" ? 1 : -1);
      return;
    }

    if (event.key === "Enter" && isOpen && activeIndex !== null) {
      event.preventDefault();
      const pair = filteredRows[activeIndex];
      if (pair !== undefined) {
        commitOption(pair.option);
      }
      return;
    }

    if (event.key === "Escape" && isOpen) {
      event.preventDefault();
      dismissList();
      return;
    }

    if (event.key === "Tab" && isOpen) {
      dismissList();
    }
  });

  sync();

  return Object.freeze({
    sync,
    isComplete: reuse.isComplete,
    isReuseAcknowledged: reuse.isReuseAcknowledged,
  });
};

const badgeTemplatePickerElements = (root, onStateChange) => ({
  fallbackField: root?.querySelector("#rule-builder-badge-template-fallback-field") ?? null,
  enhancedField: root?.querySelector("#rule-builder-badge-template-enhanced-field") ?? null,
  comboboxInput: root?.querySelector("#rule-builder-badge-template-combobox") ?? null,
  select: root?.querySelector("#rule-builder-badge-template-select") ?? null,
  listbox: root?.querySelector("#rule-builder-badge-template-listbox") ?? null,
  searchStatus: root?.querySelector("#rule-builder-badge-template-search-status") ?? null,
  reusePanel: root?.querySelector("#rule-builder-badge-template-reuse") ?? null,
  reuseMessage: root?.querySelector("#rule-builder-badge-template-reuse-message") ?? null,
  reuseConfirmation:
    root?.querySelector("#rule-builder-badge-template-reuse-confirmation") ?? null,
  onStateChange,
});

const createBadgeTemplatePickerController = (root, onStateChange) => {
  const input = badgeTemplatePickerElements(root, onStateChange);
  const { fallbackField, enhancedField, comboboxInput, select, listbox, searchStatus } = input;
  const options = selectableTemplateOptions(select);
  const canEnhance =
    fallbackField instanceof HTMLElement &&
    enhancedField instanceof HTMLElement &&
    comboboxInput instanceof HTMLInputElement &&
    select instanceof HTMLSelectElement &&
    listbox instanceof HTMLElement &&
    searchStatus instanceof HTMLElement &&
    options.length > 0;

  if (!canEnhance) {
    return createFallbackBadgeTemplatePickerController(input);
  }

  return createEnhancedBadgeTemplatePickerController({ ...input, options });
};

const ruleBuilderBadgeTemplatePicker = createBadgeTemplatePickerController(
  ruleBuilderBadgeTemplatePickerRoot,
  () => updateStepNavigationState(),
);
