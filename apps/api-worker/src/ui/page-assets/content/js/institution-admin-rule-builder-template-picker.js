const createBadgeTemplatePickerController = (input) => {
  const {
    fallbackField,
    enhancedField,
    comboboxInput,
    select,
    listbox,
    searchStatus,
    reusePanel,
    reuseMessage,
    reuseConfirmation,
    onStateChange,
  } = input;
  const options =
    select instanceof HTMLSelectElement
      ? Array.from(select.options).filter(
          (option) => option.value.trim().length > 0 && !option.disabled,
        )
      : [];

  let committedOption = null;
  let optionRows = [];
  let filteredRows = [];
  let activeIndex = null;
  let isOpen = false;
  let isEnhanced = false;
  let announcementTimer = null;

  const selectedOption = () => {
    if (!(select instanceof HTMLSelectElement)) {
      return null;
    }

    const option = select.selectedOptions[0];
    return option instanceof HTMLOptionElement && option.value.trim().length > 0 ? option : null;
  };

  const optionTitle = (option) => option.dataset.templateTitle?.trim() ?? "";
  const defaultStatusText =
    searchStatus instanceof HTMLElement ? (searchStatus.textContent ?? "") : "";

  const cancelAnnouncement = () => {
    if (announcementTimer !== null) {
      clearTimeout(announcementTimer);
      announcementTimer = null;
    }
  };

  const announceResults = (visibleCount) => {
    if (!(searchStatus instanceof HTMLElement)) {
      return;
    }

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

  const syncValidity = () => {
    if (!(comboboxInput instanceof HTMLInputElement)) {
      return;
    }

    comboboxInput.setCustomValidity(
      committedOption === null ? "Choose a badge template from the list." : "",
    );
  };

  const syncSelectedRows = () => {
    optionRows.forEach(({ option, row }) => {
      const isSelected = committedOption !== null && option.value === committedOption.value;
      row.setAttribute("aria-selected", isSelected ? "true" : "false");
      row.classList.toggle("is-selected", isSelected);
    });
  };

  const clearActiveRow = () => {
    optionRows.forEach(({ row }) => row.classList.remove("is-active"));
    activeIndex = null;

    if (comboboxInput instanceof HTMLInputElement) {
      comboboxInput.removeAttribute("aria-activedescendant");
    }
  };

  const setActiveRow = (index) => {
    clearActiveRow();

    const pair = filteredRows[index];
    if (pair === undefined || !(comboboxInput instanceof HTMLInputElement)) {
      return;
    }

    activeIndex = index;
    pair.row.classList.add("is-active");
    comboboxInput.setAttribute("aria-activedescendant", pair.row.id);
    pair.row.scrollIntoView({ block: "nearest" });
  };

  const filterRows = (query) => {
    const normalizedQuery = query.trim().normalize("NFKC").toLocaleLowerCase();
    filteredRows = optionRows.filter(({ option, row }) => {
      const isVisible =
        normalizedQuery.length === 0 ||
        optionTitle(option).normalize("NFKC").toLocaleLowerCase().includes(normalizedQuery);
      row.hidden = !isVisible;
      return isVisible;
    });

    clearActiveRow();
    const emptyRow = listbox instanceof HTMLElement ? listbox.querySelector("[data-empty-result]") : null;
    if (emptyRow instanceof HTMLElement) {
      emptyRow.hidden = filteredRows.length > 0;
    }
    announceResults(filteredRows.length);
  };

  const openList = (showAll = false) => {
    if (!(comboboxInput instanceof HTMLInputElement) || !(listbox instanceof HTMLElement)) {
      return;
    }

    if (showAll) {
      filterRows("");
    } else {
      filterRows(comboboxInput.value);
    }
    listbox.hidden = false;
    comboboxInput.setAttribute("aria-expanded", "true");
    isOpen = true;
  };

  const closeList = (restoreTitle = true, restoreStatus = false) => {
    cancelAnnouncement();
    clearActiveRow();

    if (listbox instanceof HTMLElement) {
      listbox.hidden = true;
    }

    if (comboboxInput instanceof HTMLInputElement) {
      comboboxInput.setAttribute("aria-expanded", "false");
      if (restoreTitle) {
        comboboxInput.value = committedOption === null ? "" : optionTitle(committedOption);
      }
    }

    if (restoreStatus && searchStatus instanceof HTMLElement) {
      searchStatus.textContent =
        committedOption === null
          ? defaultStatusText
          : optionTitle(committedOption) + " selected.";
    }

    isOpen = false;
  };

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

    const option = selectedOption();
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

  const sync = (resetConfirmation = false) => {
    committedOption = selectedOption();
    closeList();
    syncSelectedRows();
    syncValidity();
    syncReuse(resetConfirmation);
  };

  const commitOption = (option) => {
    if (
      !(select instanceof HTMLSelectElement) ||
      !(comboboxInput instanceof HTMLInputElement) ||
      !(option instanceof HTMLOptionElement)
    ) {
      return;
    }

    select.value = option.value;
    committedOption = option;
    syncSelectedRows();
    syncValidity();
    closeList();
    if (searchStatus instanceof HTMLElement) {
      searchStatus.textContent = optionTitle(option) + " selected.";
    }
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

  const isComplete = () => {
    return !(
      reuseConfirmation instanceof HTMLInputElement &&
      reuseConfirmation.required &&
      !reuseConfirmation.checked
    );
  };

  const isReuseAcknowledged = () => {
    return (
      reuseConfirmation instanceof HTMLInputElement &&
      reuseConfirmation.required &&
      reuseConfirmation.checked
    );
  };

  if (select instanceof HTMLSelectElement) {
    select.addEventListener("change", () => {
      if (isEnhanced) {
        sync(true);
      } else {
        syncReuse(true);
      }
      if (typeof onStateChange === "function") {
        onStateChange();
      }
    });
  }
  if (reuseConfirmation instanceof HTMLInputElement) {
    reuseConfirmation.addEventListener("change", () => {
      if (typeof onStateChange === "function") {
        onStateChange();
      }
    });
  }

  if (
    !(fallbackField instanceof HTMLElement) ||
    !(enhancedField instanceof HTMLElement) ||
    !(comboboxInput instanceof HTMLInputElement) ||
    !(select instanceof HTMLSelectElement) ||
    !(listbox instanceof HTMLElement) ||
    !(searchStatus instanceof HTMLElement) ||
    options.length === 0
  ) {
    syncReuse();
    return Object.freeze({ sync, isComplete, isReuseAcknowledged });
  }

  optionRows = options.map((option, index) => {
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
        "Used by " +
        String(usageCount) +
        (usageCount === 1 ? " other rule" : " other rules");
      row.append(usage);
    }

    row.addEventListener("pointerdown", (event) => event.preventDefault());
    row.addEventListener("click", () => {
      comboboxInput.focus();
      commitOption(option);
    });
    return { option, row };
  });

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
  isEnhanced = true;

  comboboxInput.addEventListener("focus", () => openList(true));
  comboboxInput.addEventListener("click", () => openList(true));
  comboboxInput.addEventListener("input", () => openList());
  comboboxInput.addEventListener("blur", () => closeList(true, true));
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
      closeList(true, true);
      return;
    }

    if (event.key === "Tab" && isOpen) {
      closeList(true, true);
    }
  });
  sync();

  return Object.freeze({ sync, isComplete, isReuseAcknowledged });
};
