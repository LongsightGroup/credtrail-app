import { z } from "zod";
import {
  emptyIssuedBadgesPageFilterValues,
  issuedBadgesAssertionPageUrl,
} from "./issued-badges-admin-helpers";
import type { AppContext } from "../app/types";
import { consumeAdminFlashCookie, setAdminFlashCookie, type AdminFlashKind } from "./admin-flash";
import {
  ADMIN_LIST_MESSAGE_MAX_LENGTH,
  type AdminListMessageTone,
  type AdminListMessageWorkspace,
} from "./admin-list-message-flash";

const relativePathSchema = z
  .string()
  .max(2048)
  .refine((path) => path.startsWith("/") && !path.startsWith("//") && !path.includes("\\"));
const receiptSchema = z.strictObject({
  publicBadgePath: relativePathSchema,
  verificationPath: relativePathSchema,
  jsonLdPath: relativePathSchema,
  recordPath: relativePathSchema,
  badgeTitle: z.string().min(1),
  recipientIdentity: z.string().min(1),
  issuedAt: z.string().datetime(),
});
export type AdminManualIssueReceipt = z.infer<typeof receiptSchema>;
const manualIssueFlashSchema = z.strictObject({
  workspace: z.literal("operations_manual_issue"),
  tone: z.enum(["success", "error"]),
  message: z.string().trim().min(1).max(ADMIN_LIST_MESSAGE_MAX_LENGTH),
  receipt: receiptSchema.optional(),
});
type AdminManualIssueFlashPayload = z.infer<typeof manualIssueFlashSchema>;

const MANUAL_ISSUE_WORKSPACE: AdminListMessageWorkspace = "operations_manual_issue";
const MANUAL_ISSUE_FLASH_KIND: AdminFlashKind = "list_message";
const normalizeManualIssueMessage = (message: string): string =>
  message.trim().slice(0, ADMIN_LIST_MESSAGE_MAX_LENGTH);

const parseManualIssueFlashPayload = (raw: string): AdminManualIssueFlashPayload | null => {
  try {
    const result = manualIssueFlashSchema.safeParse(JSON.parse(raw));
    return result.success ? result.data : null;
  } catch {
    return null;
  }
};

/** Builds a receipt from the persisted credential after successful issuance. */
export const buildAdminManualIssueReceipt = (input: {
  readonly publicBadgePath: string;
  readonly tenantId: string;
  readonly assertionId: string;
  readonly badgeTitle: string;
  readonly recipientIdentity: string;
  readonly issuedAt: string;
}): AdminManualIssueReceipt => ({
  publicBadgePath: input.publicBadgePath,
  verificationPath: `${input.publicBadgePath}/verification`,
  jsonLdPath: `${input.publicBadgePath}/jsonld`,
  recordPath: issuedBadgesAssertionPageUrl(
    input.tenantId,
    emptyIssuedBadgesPageFilterValues(),
    input.assertionId,
    "audit",
  ),
  badgeTitle: input.badgeTitle,
  recipientIdentity: input.recipientIdentity,
  issuedAt: input.issuedAt,
});

export const setAdminManualIssueFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: AdminListMessageTone;
    message: string;
    receipt?: AdminManualIssueReceipt;
  },
): Promise<void> => {
  const message = normalizeManualIssueMessage(input.message);

  if (message.length === 0) {
    return;
  }

  await setAdminFlashCookie(c, {
    kind: MANUAL_ISSUE_FLASH_KIND,
    tenantId: input.tenantId,
    userId: input.userId,
    value: JSON.stringify({
      workspace: MANUAL_ISSUE_WORKSPACE,
      tone: input.tone,
      message,
      ...(input.tone === "success" && input.receipt !== undefined
        ? { receipt: input.receipt }
        : {}),
    } satisfies AdminManualIssueFlashPayload),
  });
};

export const consumeAdminManualIssueFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
  },
): Promise<{
  tone: AdminListMessageTone;
  message: string;
  receipt?: AdminManualIssueReceipt;
} | null> => {
  const raw = await consumeAdminFlashCookie(c, {
    kind: MANUAL_ISSUE_FLASH_KIND,
    tenantId: input.tenantId,
    userId: input.userId,
  });

  if (raw === null) {
    return null;
  }

  const payload = parseManualIssueFlashPayload(raw);

  if (payload === null) {
    return null;
  }

  return {
    tone: payload.tone,
    message: payload.message,
    ...(payload.receipt === undefined ? {} : { receipt: payload.receipt }),
  };
};
