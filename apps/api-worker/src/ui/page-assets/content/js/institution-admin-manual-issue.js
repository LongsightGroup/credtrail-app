const issueForm = document.getElementById("manual-issue-form");
const consequence = document.getElementById("manual-issue-consequence");
const correction = document.getElementById("manual-issue-error");
const previousAward = document.getElementById("manual-issue-previous-award");
if (correction instanceof HTMLElement) correction.focus();
else if (previousAward instanceof HTMLElement) previousAward.focus();
if (issueForm instanceof HTMLFormElement && consequence instanceof HTMLElement) {
  const updateConsequence = () => {
    const recipient = issueForm.elements.namedItem("recipientIdentity");
    const badge = issueForm.elements.namedItem("badgeTemplateId");
    const title = badge instanceof HTMLSelectElement
      ? (badge.value ? badge.selectedOptions[0]?.textContent : "")
      : consequence.dataset.badgeTitle;
    const preview = document.getElementById("manual-issue-badge-preview");
    const description = document.getElementById("manual-issue-badge-description");
    if (preview instanceof HTMLElement) preview.hidden = !title;
    if (description instanceof HTMLElement && badge instanceof HTMLSelectElement) description.textContent = badge.selectedOptions[0]?.dataset.description ?? "";
    const heading = document.getElementById("manual-issue-badge-title");
    const image = document.getElementById("manual-issue-badge-image");
    if (heading instanceof HTMLElement && title) heading.textContent = title;
    if (image instanceof HTMLImageElement && badge instanceof HTMLSelectElement) {
      const uri = badge.selectedOptions[0]?.dataset.imageUri;
      image.hidden = !uri;
      if (uri) { image.src = uri; image.alt = title + " artwork"; }
    }
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
  let submitLabel = submit?.textContent ?? "Issue badge";
  issueForm.addEventListener("input", (event) => {
    const field = event.target;
    if (!(field instanceof HTMLInputElement || field instanceof HTMLSelectElement) ||
        !["recipientIdentity", "badgeTemplateId"].includes(field.name)) return;
    if (previousAward instanceof HTMLElement) previousAward.hidden = true;
    const confirmation = issueForm.elements.namedItem("previousAwardConfirmation");
    if (confirmation instanceof HTMLInputElement) confirmation.disabled = true;
    submitLabel = "Issue badge";
    if (submit instanceof HTMLButtonElement && !submitting) submit.textContent = submitLabel;
  });
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
    if (submit instanceof HTMLButtonElement) { submit.disabled = false; submit.textContent = submitLabel; }
    if (progress instanceof HTMLElement) progress.textContent = "";
  });
}
