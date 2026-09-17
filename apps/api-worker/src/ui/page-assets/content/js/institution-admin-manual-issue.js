const issueForm = document.getElementById("manual-issue-form");
const consequence = document.getElementById("manual-issue-consequence");
const correction = document.getElementById("manual-issue-error");
if (correction instanceof HTMLElement) correction.focus();
if (issueForm instanceof HTMLFormElement && consequence instanceof HTMLElement) {
  const updateConsequence = () => {
    const recipient = issueForm.elements.namedItem("recipientIdentity");
    const badge = issueForm.elements.namedItem("badgeTemplateId");
    const title = badge instanceof HTMLSelectElement
      ? (badge.value ? badge.selectedOptions[0]?.textContent : "")
      : consequence.dataset.badgeTitle;
    const email = recipient instanceof HTMLInputElement ? recipient.value.trim() : "";
    consequence.textContent = title && email
      ? "Issue " + title + " to " + email + ". This creates a credential with a public verification page."
      : "This creates a credential with a public verification page for the selected badge and recipient.";
  };
  issueForm.addEventListener("input", updateConsequence);
  issueForm.addEventListener("change", updateConsequence);
  updateConsequence();
}
if (issueForm instanceof HTMLFormElement) {
  let submitting = false;
  const submit = issueForm.querySelector('button[type="submit"]');
  const progress = document.getElementById("manual-issue-progress");
  issueForm.addEventListener("submit", (event) => {
    if (submitting) { event.preventDefault(); return; }
    submitting = true;
    issueForm.setAttribute("aria-busy", "true");
    if (submit instanceof HTMLButtonElement) { submit.disabled = true; submit.textContent = "Issuing…"; }
    if (progress instanceof HTMLElement) progress.textContent = "Issuing the badge. Please wait for the receipt.";
  });
  window.addEventListener("pageshow", () => {
    submitting = false;
    issueForm.removeAttribute("aria-busy");
    if (submit instanceof HTMLButtonElement) { submit.disabled = false; submit.textContent = "Issue badge"; }
    if (progress instanceof HTMLElement) progress.textContent = "";
  });
}
