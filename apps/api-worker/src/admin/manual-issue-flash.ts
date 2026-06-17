import type { AppContext } from "../app";
import { consumeAdminFlashCookie, setAdminFlashCookie, type AdminFlashKind } from "./admin-flash";
import {
  ADMIN_LIST_MESSAGE_MAX_LENGTH,
  type AdminListMessageTone,
  type AdminListMessageWorkspace,
} from "./admin-list-message-flash";

export interface AdminManualIssueSuccessLinks {
  publicBadgePath: string;
  verificationPath: string;
  jsonLdPath: string;
}

interface AdminManualIssueFlashPayload {
  workspace: "operations_manual_issue";
  tone: AdminListMessageTone;
  message: string;
  successLinks?: AdminManualIssueSuccessLinks;
}

const MANUAL_ISSUE_WORKSPACE: AdminListMessageWorkspace = "operations_manual_issue";
const MANUAL_ISSUE_FLASH_KIND: AdminFlashKind = "list_message";
const MANUAL_ISSUE_LINK_MAX_LENGTH = 2048;

const normalizeManualIssueMessage = (message: string): string => {
  return message.trim().slice(0, ADMIN_LIST_MESSAGE_MAX_LENGTH);
};

const normalizeRelativePath = (value: unknown): string | null => {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();

  if (trimmed.length === 0 || !trimmed.startsWith("/")) {
    return null;
  }

  return trimmed.slice(0, MANUAL_ISSUE_LINK_MAX_LENGTH);
};

const parseSuccessLinks = (value: unknown): AdminManualIssueSuccessLinks | null => {
  if (value === null || typeof value !== "object") {
    return null;
  }

  const record = value as Partial<Record<keyof AdminManualIssueSuccessLinks, unknown>>;
  const publicBadgePath = normalizeRelativePath(record.publicBadgePath);
  const verificationPath = normalizeRelativePath(record.verificationPath);
  const jsonLdPath = normalizeRelativePath(record.jsonLdPath);

  if (publicBadgePath === null || verificationPath === null || jsonLdPath === null) {
    return null;
  }

  return {
    publicBadgePath,
    verificationPath,
    jsonLdPath,
  };
};

const parseManualIssueFlashPayload = (raw: string): AdminManualIssueFlashPayload | null => {
  let parsed: unknown;

  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }

  if (parsed === null || typeof parsed !== "object") {
    return null;
  }

  const record = parsed as Partial<AdminManualIssueFlashPayload>;

  if (
    record.workspace !== MANUAL_ISSUE_WORKSPACE ||
    (record.tone !== "success" && record.tone !== "error") ||
    typeof record.message !== "string"
  ) {
    return null;
  }

  const message = normalizeManualIssueMessage(record.message);

  if (message.length === 0) {
    return null;
  }

  const successLinks = record.tone === "success" ? parseSuccessLinks(record.successLinks) : null;

  return {
    workspace: MANUAL_ISSUE_WORKSPACE,
    tone: record.tone,
    message,
    ...(successLinks === null ? {} : { successLinks }),
  };
};

export const buildAdminManualIssueSuccessLinks = (
  publicBadgePath: string,
): AdminManualIssueSuccessLinks => {
  return {
    publicBadgePath,
    verificationPath: `${publicBadgePath}/verification`,
    jsonLdPath: `${publicBadgePath}/jsonld`,
  };
};

export const setAdminManualIssueFlash = async (
  c: AppContext,
  input: {
    tenantId: string;
    userId: string;
    tone: AdminListMessageTone;
    message: string;
    successLinks?: AdminManualIssueSuccessLinks;
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
      ...(input.tone === "success" && input.successLinks !== undefined
        ? { successLinks: input.successLinks }
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
  successLinks?: AdminManualIssueSuccessLinks;
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
    ...(payload.successLinks === undefined ? {} : { successLinks: payload.successLinks }),
  };
};
