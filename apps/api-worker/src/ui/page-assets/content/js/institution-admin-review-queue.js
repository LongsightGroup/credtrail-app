const reviewForm = document.getElementById("review-decision-form");
const reviewError = document.getElementById("review-decision-error");
if (reviewError instanceof HTMLElement) reviewError.focus();
if (reviewForm instanceof HTMLFormElement) {
  const note = reviewForm.elements.namedItem("comment");
  const status = document.getElementById("review-note-state");
  let submitting = false;
  const warn = (event) => { event.preventDefault(); event.returnValue = ""; };
  const update = () => {
    const dirty = note instanceof HTMLTextAreaElement && note.value.length > 0;
    window.removeEventListener("beforeunload", warn);
    if (dirty && !submitting) window.addEventListener("beforeunload", warn);
    if (status instanceof HTMLElement && !submitting) status.textContent = dirty ? "Your decision note has not been saved." : "";
  };
  reviewForm.addEventListener("input", update);
  reviewForm.addEventListener("submit", (event) => {
    if (submitting) { event.preventDefault(); return; }
    submitting = true;
    window.removeEventListener("beforeunload", warn);
    reviewForm.setAttribute("aria-busy", "true");
    if (status instanceof HTMLElement) status.textContent = "Saving your decision. Please wait.";
  });
  window.addEventListener("pageshow", () => { submitting = false; reviewForm.removeAttribute("aria-busy"); update(); });
  update();
}
