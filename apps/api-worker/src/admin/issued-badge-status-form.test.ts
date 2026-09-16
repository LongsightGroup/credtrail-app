import { expect, it } from "vitest";
import { parseIssuedBadgeStatusForm } from "./issued-badge-status-form";

const submission = (reason: string): FormData => {
  const form = new FormData();
  form.set("toState", "suspended");
  form.set("reasonCode", "administrative_hold");
  form.set("reason", reason);
  return form;
};
it("accepts a 512-character reason", () => {
  const result = parseIssuedBadgeStatusForm(submission("x".repeat(512)));
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("Expected valid submission");
  expect(result.value.reason).toHaveLength(512);
});
it("preserves a 513-character reason and the selected action for correction", () => {
  const result = parseIssuedBadgeStatusForm(submission("x".repeat(513)));
  expect(result).toEqual({
    ok: false,
    error: {
      targetState: "suspended",
      reasonCode: "administrative_hold",
      reason: "x".repeat(513),
      message: "Shorten the reason details to 512 characters or fewer.",
    },
  });
});
it("accepts empty optional details", () => {
  const result = parseIssuedBadgeStatusForm(submission(""));
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("Expected valid submission");
  expect(result.value.reason).toBeUndefined();
});
it("requires confirmation for revocation without discarding the reason", () => {
  const form = submission("Entered details");
  form.set("toState", "revoked");
  const result = parseIssuedBadgeStatusForm(form);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("Expected confirmation error");
  expect(result.error.reason).toBe("Entered details");
  expect(result.error.message).toContain("Confirm that revocation is permanent");
  form.set("confirmRevocation", "yes");
  expect(parseIssuedBadgeStatusForm(form).ok).toBe(true);
});
