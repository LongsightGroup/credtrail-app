export const INSTITUTION_ADMIN_BADGE_TEMPLATE_LIST_RECORDS_JS = `
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
`;
