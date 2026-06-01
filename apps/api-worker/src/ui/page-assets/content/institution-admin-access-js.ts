export const INSTITUTION_ADMIN_ACCESS_JS = `
(() => {
  document.querySelectorAll('form[data-confirm-message]').forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    form.addEventListener('submit', (event) => {
      const message = form.dataset.confirmMessage ?? 'Continue?';

      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });
})();
`;
