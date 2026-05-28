export const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_RECORDS_JS = `
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
  const updateBadgeTemplateImageRevisionHint = (badgeTemplateId, revisionCount) => {
    if (typeof badgeTemplateId !== 'string' || badgeTemplateId.length === 0) {
      return;
    }

    document
      .querySelectorAll('[data-template-history-template-id="' + badgeTemplateId + '"]')
      .forEach((historyButton) => {
        if (historyButton instanceof HTMLElement) {
          historyButton.dataset.templateHistoryImageRevisionCount = String(revisionCount);
        }
      });
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
  const badgeTemplateAdminTableRowPath = (badgeTemplateId) => {
    const queryString = buildBadgeTemplateListPageQueryString();
    const suffix = queryString.length > 0 ? '?' + queryString : '';

    return (
      badgeTemplateAdminTableRowPathPrefix +
      '/' +
      encodeURIComponent(badgeTemplateId) +
      '/table-row' +
      suffix
    );
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
  const updateBadgeTemplatePreviewImage = (badgeTemplateId, imageUri) => {
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
`;
