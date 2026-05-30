import type { Context } from "hono";
import type { SqlDatabase } from "@credtrail/db";
import {
  parseBadgeTemplateAuditLogQuery,
  parseBadgeTemplatePathParams,
} from "@credtrail/validation";
import type { AppEnv } from "../app";
import { loadBadgeTemplateHistoryPayload } from "./badge-template-history-access";

type BadgeTemplateHistoryJsonContext = Context<AppEnv>;

export const respondWithBadgeTemplateHistoryJson = async (
  c: BadgeTemplateHistoryJsonContext,
  input: {
    db: SqlDatabase;
    tenantId: string;
    badgeTemplateId: string;
    limit: number;
  },
): Promise<Response> => {
  const { timeline, imageRevisionCount } = await loadBadgeTemplateHistoryPayload(input.db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    limit: input.limit,
  });

  return c.json({
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    timeline,
    imageRevisionCount,
  });
};

export const handleBadgeTemplateHistoryJsonGet = async (
  c: BadgeTemplateHistoryJsonContext,
  input: {
    db: SqlDatabase;
    invalidQueryMessage: string;
  },
): Promise<Response> => {
  const pathParams = parseBadgeTemplatePathParams(c.req.param());
  let query;

  try {
    query = parseBadgeTemplateAuditLogQuery(c.req.query());
  } catch {
    return c.json(
      {
        error: input.invalidQueryMessage,
      },
      400,
    );
  }

  return respondWithBadgeTemplateHistoryJson(c, {
    db: input.db,
    tenantId: pathParams.tenantId,
    badgeTemplateId: pathParams.badgeTemplateId,
    limit: query.limit ?? 100,
  });
};
