import { assertValidIsoTimestamp, createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import type {
  AssertionEngagementEventRecord,
  AssertionEngagementEventType,
  ListAssertionEngagementEventsInput,
  RecordAssertionEngagementEventInput,
  RecordAssertionEngagementEventResult,
} from "./assertion-types.js";
import {
  mapAssertionEngagementEventRow,
  ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES,
} from "./assertion-internal.js";
import type { AssertionEngagementEventRow } from "./assertion-internal.js";
import { findAssertionById } from "./assertion-reads.js";
import {
  backfillAssertionReportingAttributionsForTenant,
  findAssertionReportingAttributionByAssertionId,
} from "./assertion-reporting-attribution.js";

export const findAssertionEngagementEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionEngagementEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

export const findAssertionEngagementEventByType = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
  eventType: AssertionEngagementEventType,
): Promise<AssertionEngagementEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionEngagementEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
          AND event_type = ?
        ORDER BY occurred_at ASC, created_at ASC, id ASC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId, eventType)
      .first<AssertionEngagementEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionEngagementEventRow(row);
};

export const listAssertionEngagementEvents = async (
  db: SqlDatabase,
  input: ListAssertionEngagementEventsInput,
): Promise<AssertionEngagementEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionEngagementEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          event_type AS eventType,
          actor_type AS actorType,
          channel,
          occurred_at AS occurredAt,
          created_at AS createdAt
        FROM assertion_engagement_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY occurred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionEngagementEventRow>();

  const result = await listStatement();

  return result.results.map((row) => mapAssertionEngagementEventRow(row));
};

export const recordAssertionEngagementEvent = async (
  db: SqlDatabase,
  input: RecordAssertionEngagementEventInput,
): Promise<RecordAssertionEngagementEventResult> => {
  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const existingAttribution = await findAssertionReportingAttributionByAssertionId(
    db,
    input.assertionId,
  );

  if (existingAttribution === null) {
    await backfillAssertionReportingAttributionsForTenant(db, input.tenantId);
  }

  if (ONE_SHOT_ASSERTION_ENGAGEMENT_EVENT_TYPES.has(input.eventType)) {
    const existingEvent = await findAssertionEngagementEventByType(
      db,
      input.tenantId,
      input.assertionId,
      input.eventType,
    );

    if (existingEvent !== null) {
      return {
        status: "already_recorded",
        event: existingEvent,
      };
    }
  }

  assertValidIsoTimestamp(input.occurredAt, "occurredAt");

  const normalizedChannel = input.channel?.trim();
  const channel =
    normalizedChannel === undefined || normalizedChannel.length === 0 ? null : normalizedChannel;
  const eventId = createPrefixedId("aee");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_engagement_events (
          id,
          tenant_id,
          assertion_id,
          event_type,
          actor_type,
          channel,
          occurred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        input.eventType,
        input.actorType,
        channel,
        input.occurredAt,
        input.occurredAt,
      )
      .run();

  await insertStatement();

  const event = await findAssertionEngagementEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion engagement event ${eventId} after insert`);
  }

  return {
    status: "recorded",
    event,
  };
};
