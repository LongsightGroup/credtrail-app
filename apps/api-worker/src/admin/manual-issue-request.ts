/** Binds a browser submission to its actor and decisions without putting personal data in the key. */
export const manualIssueIdempotencyKey = async (input: {
  readonly tenantId: string;
  readonly userId: string;
  readonly requestId: string;
  readonly badgeTemplateId: string;
  readonly recipientIdentity: string;
  readonly pathwayHandoffId: string | undefined;
}): Promise<string> => {
  const bytes = new TextEncoder().encode(
    JSON.stringify([
      input.tenantId,
      input.userId,
      input.requestId,
      input.badgeTemplateId,
      input.recipientIdentity.trim().toLowerCase(),
      input.pathwayHandoffId ?? null,
    ]),
  );
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return "manual-form:" + Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
};
