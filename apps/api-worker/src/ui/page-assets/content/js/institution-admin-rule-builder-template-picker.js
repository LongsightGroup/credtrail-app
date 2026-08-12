const createBadgeTemplatePickerController = (input) => {
  const {
    searchField,
    searchInput,
    select,
    searchStatus,
    reusePanel,
    reuseMessage,
    reuseConfirmation,
    onStateChange,
  } = input;
  const options =
    select instanceof HTMLSelectElement
      ? Array.from(select.options).filter((option) => option.value.trim().length > 0)
      : [];

  const selectedOption = () => {
    if (!(select instanceof HTMLSelectElement)) {
      return null;
    }

    const option = select.selectedOptions[0];
    return option instanceof HTMLOptionElement && option.value.trim().length > 0 ? option : null;
  };

  const syncSearch = () => {
    if (!(searchInput instanceof HTMLInputElement) || !(searchStatus instanceof HTMLElement)) {
      return;
    }

    const query = searchInput.value.trim().toLocaleLowerCase();
    let visibleCount = 0;

    options.forEach((option) => {
      const searchText = (option.dataset.templateSearchText ?? "").toLocaleLowerCase();
      const isVisible = query.length === 0 || searchText.includes(query) || option.selected;
      option.hidden = !isVisible;
      option.disabled = !isVisible;

      if (isVisible) {
        visibleCount += 1;
      }
    });

    if (query.length === 0) {
      searchStatus.textContent =
        String(options.length) +
        (options.length === 1
          ? " badge template ready for rules, A to Z."
          : " badge templates ready for rules, A to Z.");
      return;
    }

    searchStatus.textContent =
      visibleCount === 0
        ? "No badge templates match this search."
        : String(visibleCount) +
          (visibleCount === 1 ? " badge template shown." : " badge templates shown.");
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
    syncSearch();
    syncReuse(resetConfirmation);
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

  if (
    searchField instanceof HTMLElement &&
    searchInput instanceof HTMLInputElement &&
    select instanceof HTMLSelectElement
  ) {
    searchField.hidden = false;
    searchInput.disabled = options.length === 0;
    searchInput.addEventListener("input", syncSearch);
    select.addEventListener("change", () => {
      sync(true);
      onStateChange();
    });
    reuseConfirmation?.addEventListener("change", onStateChange);
    sync();
  }

  return Object.freeze({
    sync,
    isComplete,
    isReuseAcknowledged,
  });
};
