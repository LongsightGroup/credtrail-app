export const INSTITUTION_ADMIN_BADGE_TEMPLATE_HISTORY_CORE_JS = `
  const initBadgeTemplateHistoryDialogFromPage = () => {
    if (!(badgeTemplateHistoryDialog instanceof HTMLDialogElement)) {
      return;
    }

    const closeButton = document.getElementById('badge-template-history-dialog-close');

    if (closeButton instanceof HTMLButtonElement) {
      closeButton.addEventListener('click', () => {
        badgeTemplateHistoryDialog.close();
      });
    }

    const autoOpenTemplateId =
      badgeTemplateHistoryDialog.dataset.autoOpenHistoryTemplateId || '';

    if (autoOpenTemplateId.length === 0) {
      return;
    }

    if (!badgeTemplateHistoryDialog.open) {
      badgeTemplateHistoryDialog.showModal();
    }
  };

  initBadgeTemplateHistoryDialogFromPage();
`;
