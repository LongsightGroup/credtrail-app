for (const mode of ["create", "edit"]) {
  const form = document.getElementById("badge-template-" + mode + "-form");
  const status = document.getElementById("badge-template-" + mode + "-status");
  if (!(form instanceof HTMLFormElement) || !(status instanceof HTMLElement)) continue;
  const snapshot = () => JSON.stringify(Array.from(new FormData(form).entries()));
  let saved = snapshot();
  let submitting = false;
  let leaving = false;
  let dirty = false;
  const warnBeforeLeaving = (event) => { event.preventDefault(); event.returnValue = ""; };
  const updateDirty = () => {
    const changed = snapshot() !== saved;
    if (changed === dirty || leaving) return;
    dirty = changed;
    if (dirty) window.addEventListener("beforeunload", warnBeforeLeaving);
    else window.removeEventListener("beforeunload", warnBeforeLeaving);
    if (!submitting) {
      status.textContent = dirty ? "Unsaved changes" : "No unsaved changes";
      status.classList.remove("ct-field__error");
    }
  };
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    leaving = false;
    submitting = false;
    form.inert = false;
    form.removeAttribute("aria-busy");
    window.removeEventListener("beforeunload", warnBeforeLeaving);
    dirty = false;
    status.textContent = "No unsaved changes";
    updateDirty();
  });
  document.addEventListener("input", updateDirty);
  document.addEventListener("change", updateDirty);
  // Repeatable metadata rows can change the form without firing an input event.
  const observer = new MutationObserver(updateDirty);
  for (const group of document.querySelectorAll("[data-trusted-repeatable]")) {
    observer.observe(group, { childList: true, subtree: true });
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitting) return;
    submitting = true;
    const submitted = snapshot();
    if (mode === "create") form.inert = true;
    form.setAttribute("aria-busy", "true");
    status.classList.remove("ct-field__error");
    status.textContent = "Saving…";
    try {
      const response = await fetch(form.action, {
        method: "POST", body: new FormData(form), headers: { Accept: "application/json" },
      });
      const destination = new URL(response.url);
      const savedResult = mode === "create" ? "created" : "saved";
      if (response.ok && response.redirected && destination.searchParams.get("details") === savedResult) {
        saved = submitted;
        if (snapshot() !== submitted) {
          status.textContent = "Your previous changes were saved. You have newer unsaved changes.";
          return;
        }
        leaving = true;
        window.removeEventListener("beforeunload", warnBeforeLeaving);
        window.location.assign(response.url);
        return;
      }
      let message = response.redirected
        ? "Your session may have ended. Keep this page open and sign in again in another tab before retrying."
        : "Your changes could not be saved. Review the fields and try again.";
      if (response.headers.get("content-type")?.includes("application/json")) {
        const result = await response.json();
        if (typeof result?.error === "string") message = result.error;
      }
      status.textContent = message;
      status.classList.add("ct-field__error");
      status.focus();
    } catch {
      status.textContent = "The save could not be confirmed. Your entries are still here. Check the template list before trying again.";
      status.classList.add("ct-field__error");
      status.focus();
    } finally {
      submitting = leaving;
      form.removeAttribute("aria-busy");
      if (!leaving) form.inert = false;
    }
  });
}
