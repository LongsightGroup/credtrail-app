export const INSTITUTION_ADMIN_REPORTING_JS = `
  if (reportingFiltersForm instanceof HTMLFormElement) {
    reportingFiltersForm.addEventListener('submit', () => {
      reportingFiltersForm.dataset.reportingSubmitState = 'pending';
      reportingFiltersForm.setAttribute('aria-busy', 'true');

      if (reportingFiltersStatus instanceof HTMLElement) {
        reportingFiltersStatus.textContent = 'Refreshing this page with the selected reporting slice...';
      }

      Array.from(reportingFiltersForm.querySelectorAll('button[type="submit"]')).forEach((candidate) => {
        if (candidate instanceof HTMLButtonElement) {
          candidate.disabled = true;
        }
      });
    });
  }

  const reportingBarGroups = Array.from(document.querySelectorAll('[data-reporting-bar-group]')).filter(
    (candidate) => candidate instanceof HTMLElement,
  );

  for (const group of reportingBarGroups) {
    const barValues = Array.from(group.querySelectorAll('[data-reporting-bar-value]')).filter(
      (candidate) => candidate instanceof HTMLElement,
    );

    if (barValues.length === 0) {
      continue;
    }

    const numericValues = barValues
      .map((candidate) => Number(candidate.getAttribute('data-reporting-bar-value') ?? '0'))
      .filter((value) => Number.isFinite(value) && value >= 0);
    const maxValue =
      numericValues.length === 0 ? 0 : numericValues.reduce((max, value) => Math.max(max, value), 0);

    for (const barValue of barValues) {
      const numericValue = Number(barValue.getAttribute('data-reporting-bar-value') ?? '0');
      const ratio = maxValue > 0 && Number.isFinite(numericValue) ? numericValue / maxValue : 0;

      barValue.style.setProperty('--ct-reporting-bar-ratio', ratio.toFixed(4));
    }
  }

  const reportingFocusSections = Array.from(
    document.querySelectorAll('[data-reporting-focus-section]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusLinks = Array.from(
    document.querySelectorAll('[data-reporting-focus-link]'),
  ).filter((candidate) => candidate instanceof HTMLElement);
  const reportingFocusSectionsById = new Map(reportingFocusSections.map((section) => [section.id, section]));
  const syncReportingFocusTarget = () => {
    const targetId = window.location.hash.length > 1 ? window.location.hash.slice(1) : '';
    const targetSection = targetId.length > 0 ? reportingFocusSectionsById.get(targetId) : undefined;
    const activeRootTargetId = targetSection?.dataset.reportingFocusRoot ?? '';

    for (const section of reportingFocusSections) {
      const isActive = targetId.length > 0 && section.id === targetId;
      section.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        section.focus({ preventScroll: true });
      }
    }

    for (const link of reportingFocusLinks) {
      const focusTarget = link.dataset.reportingFocusTarget ?? '';
      const isRootLink = link.hasAttribute('data-reporting-root-link');
      const isActive =
        (targetId.length > 0 && focusTarget === targetId) ||
        (isRootLink && activeRootTargetId.length > 0 && focusTarget === activeRootTargetId);

      link.dataset.reportingFocusActive = isActive ? 'true' : 'false';

      if (isActive) {
        link.setAttribute('aria-current', isRootLink ? 'location' : 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    }
  };

  if (reportingFocusSections.length > 0 || reportingFocusLinks.length > 0) {
    syncReportingFocusTarget();
    window.addEventListener('hashchange', syncReportingFocusTarget);
  }

  /* ── Mobile sidebar toggle ── */
  const sidebarToggle = document.querySelector('[data-sidebar-toggle]');
  const sidebar = document.querySelector('.ct-admin-sidebar');

  if (sidebarToggle instanceof HTMLElement && sidebar instanceof HTMLElement) {
    sidebarToggle.addEventListener('click', () => {
      sidebar.classList.toggle('ct-admin-sidebar--open');
    });

    document.addEventListener('click', (event) => {
      if (
        sidebar.classList.contains('ct-admin-sidebar--open') &&
        !sidebar.contains(event.target) &&
        event.target !== sidebarToggle
      ) {
        sidebar.classList.remove('ct-admin-sidebar--open');
      }
    });
  }
})();
`;
