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
