import type { AppContext } from "../app";
import { consumeAdminFlashCookie, setAdminFlashCookie, type AdminFlashKind } from "./admin-flash";

export const ADMIN_LIST_MESSAGE_MAX_LENGTH = 200;

export type AdminListMessageWorkspace =
  | "rules"
  | "operations_review_queue"
  | "operations"
  | "issued_badges"
  | "access_members"
  | "access_governance"
  | "access_governance_delegation"
  | "access_authentication"
  | "access_org_units"
  | "access_api_keys"
  | "access_lms_connections"
  | "operations_manual_issue"
  | "badge_templates";

export type AdminListMessageTone = "success" | "error";

interface AdminListMessageFlashPayload {
  workspace: AdminListMessageWorkspace;
  tone: AdminListMessageTone;
  message: string;
}

const LIST_MESSAGE_FLASH_KIND: AdminFlashKind = "list_message";

const normalizeListMessage = (message: string): string => {
  return message.trim().slice(0, ADMIN_LIST_MESSAGE_MAX_LENGTH);
};

const parseListMessageFlashPayload = (
  raw: string,
  workspace: AdminListMessageWorkspace,
): AdminListMessageFlashPayload | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object") {
    return null;
  }

  const record = parsed as Partial<AdminListMessageFlashPayload>;

  if (
    record.workspace !== workspace ||
    (record.tone !== "success" && record.tone !== "error") ||
    typeof record.message !== "string"
  ) {
    return null;
  }

  const message = normalizeListMessage(record.message);

  if (message.length === 0) {
    return null;
  }

  return {
    workspace: record.workspace,
    tone: record.tone,
    message,
  };
};

export const setAdminListMessageFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    workspace: AdminListMessageWorkspace;
    tone: AdminListMessageTone;
    message: string;
  },
): Promise<void> => {
  const message = normalizeListMessage(input.message);

  if (message.length === 0) {
    return;
  }

  await setAdminFlashCookie(c, {
    kind: LIST_MESSAGE_FLASH_KIND,
    tenantId: input.tenantId,
    userId: input.userId,
    value: JSON.stringify({
      workspace: input.workspace,
      tone: input.tone,
      message,
    } satisfies AdminListMessageFlashPayload),
  });
};

export const consumeAdminListMessageFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    workspace: AdminListMessageWorkspace;
  },
): Promise<{ tone: AdminListMessageTone; message: string } | null> => {
  const raw = await consumeAdminFlashCookie(c, {
    kind: LIST_MESSAGE_FLASH_KIND,
    tenantId: input.tenantId,
    userId: input.userId,
  });

  if (raw === null) {
    return null;
  }

  const payload = parseListMessageFlashPayload(raw, input.workspace);

  if (payload === null) {
    return null;
  }

  return {
    tone: payload.tone,
    message: payload.message,
  };
};
