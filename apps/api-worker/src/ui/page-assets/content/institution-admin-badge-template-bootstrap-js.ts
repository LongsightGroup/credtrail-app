export const INSTITUTION_ADMIN_BADGE_TEMPLATE_BOOTSTRAP_JS = `
(() => {
  const contextElement = document.getElementById('ct-admin-context');

  if (!(contextElement instanceof HTMLElement)) {
    return;
  }

  let parsedContext;

  try {
    parsedContext = JSON.parse(contextElement.dataset.contextJson ?? '{}');
  } catch {
    return;
  }

  const tenantAdminPath =
    parsedContext && typeof parsedContext.tenantAdminPath === 'string'
      ? parsedContext.tenantAdminPath
      : '';
  const badgeTemplateApiPathPrefix =
    parsedContext && typeof parsedContext.badgeTemplateApiPathPrefix === 'string'
      ? parsedContext.badgeTemplateApiPathPrefix
      : '';
  const badgeTemplateAdminTableRowPathPrefix =
    parsedContext && typeof parsedContext.badgeTemplateAdminTableRowPathPrefix === 'string'
      ? parsedContext.badgeTemplateAdminTableRowPathPrefix
      : tenantAdminPath.length === 0
        ? ''
        : tenantAdminPath + '/rules/templates';
  const badgeTemplateEditorPathPrefix =
    parsedContext && typeof parsedContext.badgeTemplateEditorPathPrefix === 'string'
      ? parsedContext.badgeTemplateEditorPathPrefix
      : badgeTemplateAdminTableRowPathPrefix;
  const ruleBuilderPath =
    parsedContext && typeof parsedContext.ruleBuilderPath === 'string'
      ? parsedContext.ruleBuilderPath
      : tenantAdminPath.length === 0
        ? ''
        : tenantAdminPath + '/rules/new';
  const showcasePath =
    parsedContext && typeof parsedContext.showcasePath === 'string'
      ? parsedContext.showcasePath
      : '';
  const badgeTemplatesReturnToRuleBuilder =
    parsedContext && parsedContext.badgeTemplatesReturnToRuleBuilder === true;
  const badgeTemplateRecordsById = new Map();
  const badgeTemplateRecordsContext =
    parsedContext && Array.isArray(parsedContext.badgeTemplateRecords)
      ? parsedContext.badgeTemplateRecords
      : [];

  badgeTemplateRecordsContext.forEach((entry) => {
    if (entry && typeof entry.id === 'string' && entry.id.length > 0) {
      badgeTemplateRecordsById.set(entry.id, entry);
    }
  });

  if (tenantAdminPath.length === 0 || badgeTemplateApiPathPrefix.length === 0) {
    return;
  }

  const adminButtonTinyClass = 'ct-admin__button ct-admin__button--tiny';
  const adminButtonTinySecondaryClass = adminButtonTinyClass + ' ct-admin__button--secondary';
  const badgeTemplateImageQueuedPollDelayMs = 15000;
  const badgeTemplateImageProcessingPollDelayMs = 10000;
  const templateCreatePanel = document.getElementById('template-create-panel');
  const badgeTemplateCreateForm = document.getElementById('badge-template-create-form');
  const badgeTemplateCreateStatus = document.getElementById('badge-template-create-status');
  const badgeTemplateCreateNextActions = document.getElementById(
    'badge-template-create-next-actions',
  );
  const badgeTemplateCreateNextCopy = document.getElementById('badge-template-create-next-copy');
  const badgeTemplateCreateRuleLink = document.querySelector('[data-template-create-rule-link]');
  const badgeTemplateCreateArtworkButton = document.querySelector(
    '[data-template-create-artwork-template-id]',
  );
  const badgeTemplateCreatePublicLink = document.querySelector(
    '[data-template-create-public-link]',
  );
  const templateEditPanel = document.getElementById('template-edit-panel');
  const badgeTemplateEditForm = document.getElementById('badge-template-edit-form');
  const badgeTemplateEditStatus = document.getElementById('badge-template-edit-status');
  const badgeTemplateEditorCriteriaLink = document.getElementById(
    'badge-template-editor-criteria-link',
  );
  const badgeTemplateEditorPublicLink = document.getElementById(
    'badge-template-editor-public-link',
  );
  const badgeTemplateEditorActivitySummary = document.getElementById(
    'badge-template-editor-activity-summary',
  );
  const badgeTemplateEditorHistoryLink = document.getElementById(
    'badge-template-editor-history-link',
  );
  const badgeTemplateImageUploadForm = document.getElementById('badge-template-image-upload-form');
  const badgeTemplateImageUploadStatus = document.getElementById(
    'badge-template-image-upload-status',
  );
  const badgeTemplateImageGenerationForm = document.getElementById(
    'badge-template-image-generation-form',
  );
  const badgeTemplateImageGenerationStatus = document.getElementById(
    'badge-template-image-generation-status',
  );
  const badgeTemplateImageGenerationPreview = document.getElementById(
    'badge-template-image-generation-preview',
  );
  const badgeTemplateImageGenerationPreviewImg = document.getElementById(
    'badge-template-image-generation-preview-img',
  );
  const badgeTemplateImageGenerationApplyButton = document.getElementById(
    'badge-template-image-generation-apply',
  );
  const badgeTemplateImageGenerationOpenLink = document.getElementById(
    'badge-template-image-generation-open',
  );
  const badgeTemplateHistoryDialog = document.getElementById('badge-template-history-dialog');
  const badgeTemplateHistoryDialogTitle = document.getElementById(
    'badge-template-history-dialog-title',
  );
  const badgeTemplateHistoryDialogSubtitle = document.getElementById(
    'badge-template-history-dialog-subtitle',
  );
  const badgeTemplateHistoryStatus = document.getElementById('badge-template-history-status');
  const badgeTemplateHistoryAuditList = document.getElementById('badge-template-history-audit-list');
  const badgeTemplateImageHistorySection = document.getElementById(
    'badge-template-image-history-section',
  );
  const badgeTemplateImageRevisionList = document.getElementById(
    'badge-template-image-revision-list',
  );
  let activeBadgeTemplateImageGeneration = null;
  let badgeTemplateImageGenerationPollTimer = null;
  let activeCreatedBadgeTemplateId = '';

  const setStatus = (el, text, isError, tone = 'info') => {
    if (!(el instanceof HTMLElement)) {
      return;
    }

    el.textContent = text;
    el.dataset.tone = isError ? 'error' : tone;
  };
  const parseJsonBody = async (response) => {
    try {
      return await response.json();
    } catch {
      return null;
    }
  };
  const errorDetailFromPayload = (payload) => {
    return payload && typeof payload.error === 'string' ? payload.error : 'Request failed';
  };
  const escapeHtml = (value) => {
    return String(value)
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  };
  const createAdminButtonElement = (className, label, attributes) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = className;
    button.textContent = label;

    Object.entries(attributes || {}).forEach(([name, value]) => {
      button.setAttribute(name, String(value));
    });

    return button;
  };
  const formatTimestamp = (value) => {
    if (typeof value !== 'string' || value.length === 0) {
      return 'n/a';
    }

    const parsed = Date.parse(value);

    if (!Number.isFinite(parsed)) {
      return value;
    }

    return new Date(parsed).toLocaleString();
  };

  const initInstitutionAdminBadgeTemplates = () => {
`;
