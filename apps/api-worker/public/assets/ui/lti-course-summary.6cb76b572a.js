(() => {
  const summaries = document.querySelectorAll("[data-lti-course-summary]");

  for (const summary of summaries) {
    const searchInput = summary.querySelector("[data-lti-course-summary-search]");
    const badgeFilter = summary.querySelector("[data-lti-course-summary-badge-filter]");
    const statusFilter = summary.querySelector("[data-lti-course-summary-status-filter]");
    const rows = Array.from(summary.querySelectorAll("[data-lti-course-summary-row]"));
    const emptyRow = summary.querySelector("[data-lti-course-summary-empty]");
    const resultCount = summary.querySelector("[data-lti-course-summary-count]");

    const applyFilters = () => {
      const searchTerm =
        searchInput instanceof HTMLInputElement ? searchInput.value.trim().toLowerCase() : "";
      const badgeValue =
        badgeFilter instanceof HTMLSelectElement ? badgeFilter.value.trim().toLowerCase() : "";
      const statusValue =
        statusFilter instanceof HTMLSelectElement ? statusFilter.value.trim().toLowerCase() : "";
      let visibleCount = 0;

      for (const row of rows) {
        const text = (row.getAttribute("data-search-text") ?? "").toLowerCase();
        const badge = (row.getAttribute("data-badge-template-id") ?? "").toLowerCase();
        const status = (row.getAttribute("data-status") ?? "").toLowerCase();
        const isVisible =
          (searchTerm.length === 0 || text.includes(searchTerm)) &&
          (badgeValue.length === 0 || badge === badgeValue) &&
          (statusValue.length === 0 || status === statusValue);

        row.hidden = !isVisible;
        if (isVisible) {
          visibleCount += 1;
        }
      }

      if (emptyRow instanceof HTMLTableRowElement) {
        emptyRow.hidden = visibleCount !== 0;
      }

      if (resultCount !== null) {
        resultCount.textContent = String(visibleCount);
      }
    };

    searchInput?.addEventListener("input", applyFilters);
    badgeFilter?.addEventListener("change", applyFilters);
    statusFilter?.addEventListener("change", applyFilters);
    applyFilters();
  }
})();
