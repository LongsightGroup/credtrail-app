import type { AppContext } from "../app";

export interface DirectIssueBadgeRequest {
  badgeTemplateId: string;
  recipientIdentity: string;
  recipientIdentityType: "email" | "email_sha256" | "did" | "url";
  idempotencyKey: string;
}

export interface DirectIssueBadgeResult {
  status: "issued" | "already_issued";
  assertionId: string;
}

interface IssueBadgeHttpErrorPayload {
  error: string;
  did?: string | undefined;
}

interface IssueBadgeHttpErrorShape {
  statusCode: 400 | 404 | 409 | 422 | 500 | 502;
  payload: IssueBadgeHttpErrorPayload;
}

export const isIssueBadgeHttpError = (error: unknown): error is IssueBadgeHttpErrorShape => {
  if (error === null || typeof error !== "object") {
    return false;
  }

  const candidate = error as Partial<IssueBadgeHttpErrorShape> & {
    payload?: { error?: unknown };
  };

  if (
    candidate.statusCode !== 400 &&
    candidate.statusCode !== 404 &&
    candidate.statusCode !== 409 &&
    candidate.statusCode !== 422 &&
    candidate.statusCode !== 500 &&
    candidate.statusCode !== 502
  ) {
    return false;
  }

  if (candidate.payload === undefined) {
    return false;
  }

  if (typeof candidate.payload.error !== "string") {
    return false;
  }

  return true;
};


export type IssueBadgeForTenant = (
  c: AppContext,
  tenantId: string,
  request: DirectIssueBadgeRequest,
  issuedByUserId?: string,
) => Promise<DirectIssueBadgeResult>;
