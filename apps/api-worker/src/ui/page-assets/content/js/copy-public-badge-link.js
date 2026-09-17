for (const container of document.querySelectorAll("[data-copy-public-badge]")) {
  const button = container.querySelector("button[data-public-badge-url]");
  const status = container.querySelector("[data-copy-status]");
  const fallback = container.querySelector("[data-copy-fallback]");
  if (!(button instanceof HTMLButtonElement) || !(status instanceof HTMLElement) || !(fallback instanceof HTMLElement)) continue;
  button.addEventListener("click", async () => {
    const url = button.dataset.publicBadgeUrl;
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      status.textContent = "Copied";
      fallback.hidden = true;
    } catch {
      status.textContent = "Select and copy the public link below.";
      fallback.hidden = false;
      const field = fallback.querySelector("input");
      if (field instanceof HTMLInputElement) { field.focus(); field.select(); }
    }
  });
}
