const badgeTemplateTableBody = document.getElementById("badge-template-table-body");
const closeActionMenuPopover = (element) => {
  window.CredTrailAdminActionMenus.close(element);
};

if (badgeTemplateTableBody instanceof HTMLElement) {
  badgeTemplateTableBody.addEventListener("click", (event) => {
    const target = event.target;

    if (!(target instanceof Element)) {
      return;
    }

    const historyTrigger = target.closest("[data-template-history-template-id]");

    if (
      historyTrigger instanceof HTMLButtonElement ||
      historyTrigger instanceof HTMLAnchorElement
    ) {
      closeActionMenuPopover(historyTrigger);
    }
  });
}
