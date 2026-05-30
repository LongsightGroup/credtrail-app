export const INSTITUTION_ADMIN_API_KEYS_JS = `
(() => {
  document.querySelectorAll('form[data-api-key-revoke-form]').forEach((form) => {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    form.addEventListener('submit', (event) => {
      const label = form.dataset.apiKeyLabel ?? 'API key';

      if (!window.confirm('Revoke key "' + label + '"? This action cannot be undone.')) {
        event.preventDefault();
      }
    });
  });
})();
`;
