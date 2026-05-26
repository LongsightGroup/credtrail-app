export const INSTITUTION_ADMIN_BADGE_TEMPLATE_RECORDS_JS = `
  const syncBadgeTemplateEditForm = (badgeTemplateId) => {
    if (!(badgeTemplateEditForm instanceof HTMLFormElement)) {
      return;
    }

    const record = badgeTemplateRecordsById.get(badgeTemplateId);

    if (record === undefined) {
      return;
    }

    const templateSelect = badgeTemplateEditForm.elements.namedItem('badgeTemplateId');
    const titleInput = badgeTemplateEditForm.elements.namedItem('title');
    const slugInput = badgeTemplateEditForm.elements.namedItem('slug');
    const descriptionInput = badgeTemplateEditForm.elements.namedItem('description');
    const criteriaUriInput = badgeTemplateEditForm.elements.namedItem('criteriaUri');

    if (templateSelect instanceof HTMLSelectElement) {
      templateSelect.value = badgeTemplateId;
    }

    if (titleInput instanceof HTMLInputElement) {
      titleInput.value = typeof record.title === 'string' ? record.title : '';
    }

    if (slugInput instanceof HTMLInputElement) {
      slugInput.value = typeof record.slug === 'string' ? record.slug : '';
    }

    if (descriptionInput instanceof HTMLTextAreaElement) {
      descriptionInput.value =
        typeof record.description === 'string' && record.description !== null
          ? record.description
          : '';
    }

    if (criteriaUriInput instanceof HTMLInputElement) {
      criteriaUriInput.value =
        typeof record.criteriaUri === 'string' && record.criteriaUri !== null
          ? record.criteriaUri
          : '';
    }

    const publicPath = badgeTemplateShowcasePath(badgeTemplateId);
    const criteriaPath = badgeTemplateCriteriaRegistryPath(badgeTemplateId);

    if (badgeTemplateEditorPublicLink instanceof HTMLAnchorElement && publicPath.length > 0) {
      badgeTemplateEditorPublicLink.href = publicPath;
    }

    if (badgeTemplateEditorCriteriaLink instanceof HTMLAnchorElement && criteriaPath.length > 0) {
      badgeTemplateEditorCriteriaLink.href = criteriaPath;
    }

    if (badgeTemplateEditorHistoryLink instanceof HTMLAnchorElement) {
      const rowHistoryTrigger = document.querySelector(
        '[data-template-history-template-id="' + badgeTemplateId + '"]',
      );
      const revisionCount =
        rowHistoryTrigger instanceof HTMLElement
          ? rowHistoryTrigger.dataset.templateHistoryImageRevisionCount || '0'
          : '0';
      badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateId = badgeTemplateId;
      badgeTemplateEditorHistoryLink.dataset.templateHistoryTemplateTitle =
        typeof record.title === 'string' ? record.title : '';
      badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount = revisionCount;
    }

    if (badgeTemplateEditorActivitySummary instanceof HTMLElement) {
      const revisionCount = readBadgeTemplateImageRevisionCount(badgeTemplateId);
      const revisionLabel =
        revisionCount === 1 ? '1 image version' : String(revisionCount) + ' image versions';
      const updatedAt =
        typeof record.updatedAt === 'string' && record.updatedAt.length > 0
          ? formatTimestamp(record.updatedAt)
          : 'n/a';
      badgeTemplateEditorActivitySummary.textContent =
        revisionLabel + '. Last updated ' + updatedAt + '.';
    }
  };
  const openTemplateEditor = (badgeTemplateId, section) => {
    syncBadgeTemplateEditForm(badgeTemplateId);
    setBadgeTemplateImageFormSelection(badgeTemplateId);

    if (templateEditPanel instanceof HTMLDetailsElement) {
      templateEditPanel.hidden = false;
      templateEditPanel.open = true;

      const sectionId =
        typeof section === 'string' && section.length > 0 ? 'template-editor-' + section : '';
      const sectionElement =
        sectionId.length > 0 ? document.getElementById(sectionId) : templateEditPanel;
      const scrollTarget = sectionElement instanceof HTMLElement ? sectionElement : templateEditPanel;
      scrollTarget.scrollIntoView({ block: 'start', behavior: 'smooth' });
    }
  };
  const setBadgeTemplateHistoryTimelineHtml = (html) => {
    if (!(badgeTemplateHistoryAuditList instanceof HTMLElement)) {
      return;
    }

    badgeTemplateHistoryAuditList.innerHTML =
      typeof html === 'string' && html.length > 0
        ? html
        : '<p class="ct-admin__empty">No edit history is recorded for this badge template yet.</p>';
  };
  const parseBadgeTemplateHistoryImageRevisionCount = (response) => {
    const countHeader = response.headers.get('X-CredTrail-Badge-Template-Image-Revision-Count');
    const parsed = countHeader === null ? 0 : Number.parseInt(countHeader, 10);

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const parseBadgeTemplateHistoryEventCount = (response) => {
    const countHeader = response.headers.get('X-CredTrail-Badge-Template-History-Event-Count');
    const parsed = countHeader === null ? 0 : Number.parseInt(countHeader, 10);

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const updateBadgeTemplateRowImage = (badgeTemplateId, imageUri) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const imageCell = row.cells.item(0);

    if (imageCell === null) {
      return;
    }

    if (typeof imageUri !== 'string' || imageUri.length === 0) {
      imageCell.innerHTML = '<span class="ct-admin__template-placeholder">No image</span>';
      return;
    }

    const link = document.createElement('a');
    link.className = 'ct-admin__template-image-link';
    link.href = imageUri;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.setAttribute('aria-label', 'Open full size badge template image');
    const thumbnail = document.createElement('img');
    thumbnail.className = 'ct-admin__template-image';
    thumbnail.src = imageUri;
    thumbnail.alt = '';
    thumbnail.loading = 'lazy';
    link.append(thumbnail);
    imageCell.textContent = '';
    imageCell.append(link);
  };
  const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const historyButton = document.querySelector(
      '[data-template-history-template-id="' + badgeTemplateId + '"]',
    );

    if (historyButton instanceof HTMLElement) {
      historyButton.dataset.templateHistoryImageRevisionCount = String(revisionCount);
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const titleCell = row.cells.item(1);

    if (titleCell === null) {
      return;
    }

    titleCell.querySelector('[data-template-image-revision-hint]')?.remove();

    if (badgeTemplateEditorHistoryLink instanceof HTMLElement) {
      badgeTemplateEditorHistoryLink.dataset.templateHistoryImageRevisionCount =
        String(revisionCount);
    }

    if (badgeTemplateEditorActivitySummary instanceof HTMLElement) {
      const record = badgeTemplateRecordsById.get(badgeTemplateId);
      const updatedAt =
        record && typeof record.updatedAt === 'string' && record.updatedAt.length > 0
          ? formatTimestamp(record.updatedAt)
          : 'n/a';
      const revisionLabel =
        revisionCount === 1 ? '1 image version' : String(revisionCount) + ' image versions';
      badgeTemplateEditorActivitySummary.textContent =
        revisionLabel + '. Last updated ' + updatedAt + '.';
    }
  };
  const readBadgeTemplateImageRevisionCount = (badgeTemplateId) => {
    const historyButton = document.querySelector(
      '[data-template-history-template-id="' + badgeTemplateId + '"]',
    );

    if (!(historyButton instanceof HTMLElement)) {
      return 0;
    }

    const parsed = Number.parseInt(
      historyButton.dataset.templateHistoryImageRevisionCount || '0',
      10,
    );

    return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed)) : 0;
  };
  const bumpBadgeTemplateImageRevisionHint = (badgeTemplateId) => {
    updateBadgeTemplateImageRevisionHint(
      badgeTemplateId,
      readBadgeTemplateImageRevisionCount(badgeTemplateId) + 1,
    );
  };
  const refreshBadgeTemplateHistoryIfOpen = async (badgeTemplateId) => {
    if (
      activeBadgeTemplateHistoryId.length === 0 ||
      activeBadgeTemplateHistoryId !== badgeTemplateId ||
      !(badgeTemplateHistoryDialog instanceof HTMLDialogElement) ||
      !badgeTemplateHistoryDialog.open
    ) {
      return;
    }

    await loadBadgeTemplateHistory(badgeTemplateId);
  };
  const updateBadgeTemplateRowDetails = (badgeTemplateId, template) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    const row = document.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (!(row instanceof HTMLTableRowElement)) {
      return;
    }

    const titleCell = row.cells.item(1);

    if (titleCell !== null && template && typeof template.title === 'string') {
      const title = titleCell.querySelector('strong');

      if (title instanceof HTMLElement) {
        title.textContent = template.title;
      }
    }

    const updatedAtCell = row.cells.item(3);

    if (updatedAtCell !== null && template && typeof template.updatedAt === 'string') {
      updatedAtCell.textContent = formatTimestamp(template.updatedAt);
    }

    document
      .querySelectorAll('[data-template-history-template-id="' + badgeTemplateId + '"]')
      .forEach((candidate) => {
        if (candidate instanceof HTMLElement && template && typeof template.title === 'string') {
          candidate.dataset.templateHistoryTemplateTitle = template.title;
        }
      });

    if (
      activeBadgeTemplateHistoryId === badgeTemplateId &&
      template &&
      typeof template.title === 'string' &&
      badgeTemplateHistoryDialogSubtitle instanceof HTMLElement
    ) {
      activeBadgeTemplateHistoryTitle = template.title;
      badgeTemplateHistoryDialogSubtitle.textContent = template.title;
    }

    if (template && typeof template.id === 'string') {
      syncBadgeTemplateEditForm(template.id);
    }
  };
  const badgeTemplateAdminTableRowPath = (badgeTemplateId) => {
    return (
      badgeTemplateAdminTableRowPathPrefix +
      '/' +
      encodeURIComponent(badgeTemplateId) +
      '/table-row'
    );
  };
  const badgeTemplateRuleBuilderPath = (badgeTemplateId) => {
    if (ruleBuilderPath.length === 0) {
      return '';
    }

    const url = new URL(ruleBuilderPath, window.location.origin);
    url.searchParams.set('badgeTemplateId', badgeTemplateId);
    return url.pathname + url.search;
  };
  const badgeTemplateShowcasePath = (badgeTemplateId) => {
    if (showcasePath.length === 0) {
      return '';
    }

    const url = new URL(showcasePath, window.location.origin);
    url.searchParams.set('badgeTemplateId', badgeTemplateId);
    return url.pathname + url.search;
  };
  const badgeTemplateCriteriaRegistryPath = (badgeTemplateId) => {
    if (showcasePath.length === 0) {
      return '';
    }

    const url = new URL(showcasePath, window.location.origin);
    url.pathname = url.pathname.replace(/\\/$/, '') + '/criteria';
    url.searchParams.set('badgeTemplateId', badgeTemplateId);
    return url.pathname + url.search;
  };
  const hideBadgeTemplateCreateNextActions = () => {
    activeCreatedBadgeTemplateId = '';

    if (badgeTemplateCreateNextActions instanceof HTMLElement) {
      badgeTemplateCreateNextActions.hidden = true;
      badgeTemplateCreateNextActions.dataset.artworkReady = 'false';
    }
  };
  const showBadgeTemplateCreateNextActions = (badgeTemplateId) => {
    if (!(badgeTemplateCreateNextActions instanceof HTMLElement)) {
      return;
    }

    activeCreatedBadgeTemplateId = badgeTemplateId;
    const rulePath = badgeTemplateRuleBuilderPath(badgeTemplateId);
    const publicPath = badgeTemplateShowcasePath(badgeTemplateId);

    if (badgeTemplateCreateRuleLink instanceof HTMLAnchorElement && rulePath.length > 0) {
      badgeTemplateCreateRuleLink.href = rulePath;
    }

    if (badgeTemplateCreatePublicLink instanceof HTMLAnchorElement && publicPath.length > 0) {
      badgeTemplateCreatePublicLink.href = publicPath;
    }

    if (badgeTemplateCreateArtworkButton instanceof HTMLButtonElement) {
      badgeTemplateCreateArtworkButton.dataset.templateCreateArtworkTemplateId = badgeTemplateId;
    }

    badgeTemplateCreateNextActions.dataset.artworkReady = 'false';

    if (badgeTemplateCreateNextCopy instanceof HTMLElement) {
      badgeTemplateCreateNextCopy.textContent = badgeTemplatesReturnToRuleBuilder
        ? 'Add badge artwork next, then continue back to the rule builder.'
        : 'Add badge artwork next, then use this template in a rule.';
    }

    badgeTemplateCreateNextActions.hidden = false;
  };
  const markBadgeTemplateCreateArtworkReady = (badgeTemplateId) => {
    if (
      activeCreatedBadgeTemplateId.length === 0 ||
      activeCreatedBadgeTemplateId !== badgeTemplateId ||
      !(badgeTemplateCreateNextActions instanceof HTMLElement)
    ) {
      return;
    }

    badgeTemplateCreateNextActions.dataset.artworkReady = 'true';

    if (badgeTemplateCreateNextCopy instanceof HTMLElement) {
      badgeTemplateCreateNextCopy.textContent = badgeTemplatesReturnToRuleBuilder
        ? 'Artwork added. Continue back to the rule builder when you are ready.'
        : 'Artwork added. Use this template in a rule when you are ready.';
    }
  };
  const removeEmptyBadgeTemplateOptions = (select) => {
    Array.from(select.options).forEach((option) => {
      if (option.value.length === 0) {
        option.remove();
      }
    });
  };
  const upsertBadgeTemplateSelectOptions = (template) => {
    if (!template || typeof template.id !== 'string' || typeof template.title !== 'string') {
      return;
    }

    document.querySelectorAll('select[name="badgeTemplateId"]').forEach((candidate) => {
      if (!(candidate instanceof HTMLSelectElement)) {
        return;
      }

      removeEmptyBadgeTemplateOptions(candidate);

      let option = Array.from(candidate.options).find((entry) => entry.value === template.id);

      if (option === undefined) {
        option = document.createElement('option');
        option.value = template.id;
        candidate.append(option);
      }

      option.textContent = template.title + ' (' + template.id + ')';
      candidate.value = template.id;
    });
  };
  const optionalTemplateText = (value, fallback) => {
    return typeof value === 'string' || value === null ? value : fallback;
  };
  const badgeTemplateSlugBaseFromTitle = (title) => {
    const normalized = title
      .trim()
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[\\u0300-\\u036f]/g, '')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .replace(/-{2,}/g, '-');

    if (normalized.length === 1) {
      return normalized + '-badge';
    }

    return normalized;
  };
  const clampBadgeTemplateSlug = (slug, maxLength) => {
    const clipped = slug.slice(0, maxLength).replace(/-+$/g, '');

    if (clipped.length >= 2) {
      return clipped;
    }

    return '';
  };
  const deriveBadgeTemplateSlugFromTitle = (title) => {
    const base = clampBadgeTemplateSlug(badgeTemplateSlugBaseFromTitle(title), 96);

    if (base.length === 0) {
      return '';
    }

    const existingSlugs = new Set();
    badgeTemplateRecordsById.forEach((record) => {
      if (record && typeof record.slug === 'string' && record.slug.length > 0) {
        existingSlugs.add(record.slug);
      }
    });

    if (!existingSlugs.has(base)) {
      return base;
    }

    for (let suffix = 2; suffix < 1000; suffix += 1) {
      const suffixText = '-' + suffix;
      const candidate = clampBadgeTemplateSlug(base, 96 - suffixText.length) + suffixText;

      if (!existingSlugs.has(candidate)) {
        return candidate;
      }
    }

    return clampBadgeTemplateSlug(base, 87) + '-' + Date.now().toString(36).slice(-8);
  };
  const normalizeBadgeTemplateRecord = (candidate, fallback) => {
    if (!candidate || typeof candidate !== 'object' || typeof candidate.id !== 'string') {
      return null;
    }

    return {
      id: candidate.id,
      slug: typeof candidate.slug === 'string' ? candidate.slug : fallback.slug,
      title: typeof candidate.title === 'string' ? candidate.title : fallback.title,
      description: optionalTemplateText(candidate.description, fallback.description),
      criteriaUri: optionalTemplateText(candidate.criteriaUri, fallback.criteriaUri),
      imageUri: optionalTemplateText(candidate.imageUri, fallback.imageUri ?? null),
      isArchived:
        typeof candidate.isArchived === 'boolean' ? candidate.isArchived : fallback.isArchived ?? false,
      updatedAt:
        typeof candidate.updatedAt === 'string' ? candidate.updatedAt : fallback.updatedAt ?? '',
    };
  };
  const parseBadgeTemplateTableRowFragment = (html) => {
    const fragment = document.createElement('template');
    fragment.innerHTML = html.trim();
    const row = fragment.content.firstElementChild;

    return row instanceof HTMLTableRowElement ? row : null;
  };
  const fetchBadgeTemplateTableRow = async (badgeTemplateId) => {
    if (badgeTemplateAdminTableRowPathPrefix.length === 0) {
      return null;
    }

    let response;

    try {
      response = await fetch(badgeTemplateAdminTableRowPath(badgeTemplateId), {
        headers: {
          accept: 'text/html',
        },
      });
    } catch {
      return null;
    }

    if (!response.ok) {
      return null;
    }

    return parseBadgeTemplateTableRowFragment(await response.text());
  };
  const upsertBadgeTemplateTableRow = async (badgeTemplateId) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return false;
    }

    const tableBody = document.getElementById('badge-template-table-body');

    if (!(tableBody instanceof HTMLTableSectionElement)) {
      return false;
    }

    const row = await fetchBadgeTemplateTableRow(badgeTemplateId);

    if (row === null) {
      return false;
    }

    tableBody.querySelectorAll('td.ct-admin__empty').forEach((emptyCell) => {
      emptyCell.closest('tr')?.remove();
    });

    const existingRow = tableBody.querySelector('[data-template-row-id="' + badgeTemplateId + '"]');

    if (existingRow instanceof HTMLTableRowElement) {
      existingRow.replaceWith(row);
    } else {
      tableBody.prepend(row);
    }

    return true;
  };
`;
