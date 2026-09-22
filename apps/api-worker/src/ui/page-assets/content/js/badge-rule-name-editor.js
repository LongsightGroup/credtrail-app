const initializeRuleNameEditor = () => {
  const editor = document.getElementById("rule-name-editor");
  if (!(editor instanceof HTMLDetailsElement)) return;
  const form = editor.querySelector("form");
  const field = editor.querySelector('input[name="name"]');
  const returnTo = editor.querySelector('input[name="returnTo"]');
  const status = editor.querySelector("[data-rule-name-status]");
  if (
    !(form instanceof HTMLFormElement) ||
    !(field instanceof HTMLInputElement) ||
    !(returnTo instanceof HTMLInputElement) ||
    !(status instanceof HTMLElement)
  )
    return;
  const inList = editor.hidden;
  let trigger = editor.querySelector("summary");
  let savedName = field.value;
  let saving = false;
  document.querySelectorAll("[data-rule-rename]").forEach((link) => {
    link.addEventListener("click", (event) => {
      if (!(link instanceof HTMLAnchorElement) || saving) return;
      event.preventDefault();
      trigger =
        link.closest(".ct-admin__action-menu")?.querySelector("[data-action-menu-trigger]") ?? link;
      window.CredTrailAdminActionMenus?.close(link);
      form.action = link.dataset.ruleRename;
      field.value = link.dataset.ruleName ?? "";
      savedName = field.value;
      status.textContent = "";
      returnTo.value = window.location.pathname + window.location.search;
      editor.hidden = false;
      editor.open = true;
      const menu = link.closest("details");
      if (menu instanceof HTMLDetailsElement) menu.open = false;
      field.focus();
      field.select();
    });
  });
  const cancel = () => {
    if (saving) return;
    field.value = savedName;
    status.textContent = "";
    editor.open = false;
    if (inList) editor.hidden = true;
    if (trigger instanceof HTMLElement) {
      const menu = trigger.closest("details");
      const focusTarget = menu && !menu.open ? menu.querySelector("summary") : trigger;
      if (focusTarget instanceof HTMLElement) focusTarget.focus();
    }
  };
  editor.querySelector("[data-rule-name-cancel]")?.addEventListener("click", cancel);
  editor.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !event.isComposing) {
      event.preventDefault();
      cancel();
    }
  });
  editor.addEventListener("toggle", () => {
    if (editor.open) {
      savedName = field.value;
      field.focus();
      field.select();
    }
  });
  if (window.location.hash === "#rule-name-editor") editor.open = true;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (saving) return;
    const body = new FormData(form);
    if (field.value.trim().length === 0) {
      status.textContent = "Enter a name.";
      field.focus();
      return;
    }
    saving = true;
    form.setAttribute("aria-busy", "true");
    const buttons = Array.from(form.querySelectorAll("button"));
    buttons.forEach((button) => {
      button.disabled = true;
    });
    status.textContent = "Saving…";
    try {
      const response = await fetch(form.action, {
        method: "POST",
        body,
        headers: { Accept: "application/json" },
      });
      const payload = await response.json();
      if (!response.ok || typeof payload.redirectTo !== "string") {
        throw new Error(
          typeof payload.error === "string"
            ? payload.error
            : "The name could not be saved. Try again.",
        );
      }
      window.location.assign(payload.redirectTo);
    } catch (error) {
      status.textContent =
        error instanceof Error ? error.message : "The name could not be saved. Try again.";
      saving = false;
      form.removeAttribute("aria-busy");
      buttons.forEach((button) => {
        button.disabled = false;
      });
      field.focus();
    }
  });
};
initializeRuleNameEditor();
