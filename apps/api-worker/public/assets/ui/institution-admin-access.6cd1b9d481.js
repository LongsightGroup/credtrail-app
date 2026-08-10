(() => {
document.querySelectorAll("form[data-confirm-message]").forEach((form) => {
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  form.addEventListener("submit", (event) => {
    const message = form.dataset.confirmMessage ?? "Continue?";

    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
});

let hasAutomaticRoleUpdates = false;

document.querySelectorAll("form[data-admin-role-form]").forEach((form) => {
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const roleSelect = form.querySelector('select[name="role"]');
  const fallbackButton = form.querySelector("[data-admin-role-submit]");

  if (
    !(roleSelect instanceof HTMLSelectElement) ||
    !(fallbackButton instanceof HTMLButtonElement)
  ) {
    return;
  }

  let isSubmitting = false;

  roleSelect.addEventListener("change", () => {
    if (isSubmitting || roleSelect.value === roleSelect.dataset.currentRole) {
      return;
    }

    isSubmitting = true;
    form.requestSubmit();
  });

  fallbackButton.hidden = true;
  hasAutomaticRoleUpdates = true;
});

const automaticRoleUpdateNote = document.querySelector("[data-admin-role-auto-save-note]");

if (hasAutomaticRoleUpdates && automaticRoleUpdateNote instanceof HTMLElement) {
  automaticRoleUpdateNote.hidden = false;
}

})();