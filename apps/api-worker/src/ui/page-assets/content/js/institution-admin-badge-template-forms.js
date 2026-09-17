for (const mode of ["create", "edit"]) {
  const form = document.getElementById("badge-template-" + mode + "-form");
  const status = document.getElementById("badge-template-" + mode + "-status");
  if (!(form instanceof HTMLFormElement) || !(status instanceof HTMLElement)) continue;
  let submitting = false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitting) return;
    submitting = true;
    form.setAttribute("aria-busy", "true");
    status.textContent = "Saving…";
    try {
      const response = await fetch(form.action, {
        method: "POST", body: new FormData(form), headers: { Accept: "application/json" },
      });
      if (response.ok && response.redirected) {
        window.location.assign(response.url);
        return;
      }
      let message = "Your changes could not be saved. Review the fields and try again.";
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
      submitting = false;
      form.removeAttribute("aria-busy");
    }
  });
}
