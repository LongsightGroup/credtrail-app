import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";
import type {
  AssertionLifecycleEventRecord,
  AssertionLifecycleState,
  AssertionLifecycleReasonCode,
  AssertionLifecycleStateByAssertionIdRecord,
  ListAssertionLifecycleEventsInput,
  ListAssertionLifecycleStatesByAssertionIdsInput,
  RecordAssertionLifecycleTransitionInput,
  RecordAssertionLifecycleTransitionResult,
  ResolveAssertionLifecycleStateResult,
} from "./assertion-types.js";
import {
  ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS,
  ASSERTION_LIFECYCLE_REASON_CODES,
  assertionLifecycleStateFromRecords,
  chunkValues,
  mapAssertionLifecycleEventRow,
  uniqueNonEmptyStrings,
  resolveAssertionLifecycleProjection,
} from "./assertion-internal.js";
import type { AssertionLifecycleEventRow } from "./assertion-internal.js";
import { findAssertionById } from "./assertion-reads.js";
import { recordAssertionRevocation } from "./assertion-writes.js";

export const findLatestAssertionLifecycleEvent = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const latestStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT 1
      `,
      )
      .bind(tenantId, assertionId)
      .first<AssertionLifecycleEventRow>();

  const row = await latestStatement();

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

export const findAssertionLifecycleEventById = async (
  db: SqlDatabase,
  id: string,
): Promise<AssertionLifecycleEventRecord | null> => {
  const lookupStatement = (): Promise<AssertionLifecycleEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(id)
      .first<AssertionLifecycleEventRow>();

  const row = await lookupStatement();

  return row === null ? null : mapAssertionLifecycleEventRow(row);
};

export const listAssertionLifecycleEvents = async (
  db: SqlDatabase,
  input: ListAssertionLifecycleEventsInput,
): Promise<AssertionLifecycleEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 50, 200));
  const listStatement = (): Promise<SqlQueryResult<AssertionLifecycleEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          assertion_id AS assertionId,
          from_state AS fromState,
          to_state AS toState,
          reason_code AS reasonCode,
          reason,
          transition_source AS transitionSource,
          actor_user_id AS actorUserId,
          transitioned_at AS transitionedAt,
          created_at AS createdAt
        FROM assertion_lifecycle_events
        WHERE tenant_id = ?
          AND assertion_id = ?
        ORDER BY transitioned_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.assertionId, queryLimit)
      .all<AssertionLifecycleEventRow>();

  const result = await listStatement();

  return result.results.map((row) => mapAssertionLifecycleEventRow(row));
};

export const resolveAssertionLifecycleState = async (
  db: SqlDatabase,
  tenantId: string,
  assertionId: string,
): Promise<ResolveAssertionLifecycleStateResult | null> => {
  const assertion = await findAssertionById(db, tenantId, assertionId);

  if (assertion === null) {
    return null;
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(db, tenantId, assertionId);
  return assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });
};

export const listAssertionLifecycleStatesByAssertionIds = async (
  db: SqlDatabase,
  input: ListAssertionLifecycleStatesByAssertionIdsInput,
): Promise<AssertionLifecycleStateByAssertionIdRecord[]> => {
  const assertionIds = uniqueNonEmptyStrings(input.assertionIds);

  if (assertionIds.length === 0) {
    return [];
  }

  const states: AssertionLifecycleStateByAssertionIdRecord[] = [];

  for (const assertionIdChunk of chunkValues(assertionIds, 400)) {
    const assertionIdPlaceholders = assertionIdChunk.map(() => "?").join(", ");
    const result = await db
      .prepare(
        `
        SELECT
          assertions.id AS assertionId,
          assertions.revoked_at AS revokedAt,
          lifecycle.to_state AS latestToState,
          lifecycle.reason_code AS latestReasonCode,
          lifecycle.reason AS latestReason,
          lifecycle.transitioned_at AS latestTransitionedAt
        FROM assertions
        LEFT JOIN assertion_lifecycle_events lifecycle
          ON lifecycle.id = (
            SELECT ale.id
            FROM assertion_lifecycle_events ale
            WHERE ale.tenant_id = assertions.tenant_id
              AND ale.assertion_id = assertions.id
            ORDER BY ale.transitioned_at DESC, ale.created_at DESC, ale.id DESC
            LIMIT 1
          )
        WHERE assertions.tenant_id = ?
          AND assertions.id IN (${assertionIdPlaceholders})
      `,
      )
      .bind(input.tenantId, ...assertionIdChunk)
      .all<{
        assertionId: string;
        revokedAt: string | null;
        latestToState: AssertionLifecycleState | null;
        latestReasonCode: AssertionLifecycleReasonCode | null;
        latestReason: string | null;
        latestTransitionedAt: string | null;
      }>();

    states.push(
      ...result.results.map((row) => {
        const lifecycle = resolveAssertionLifecycleProjection({
          revokedAt: row.revokedAt,
          latestToState: row.latestToState,
          latestReasonCode: row.latestReasonCode,
          latestReason: row.latestReason,
          latestTransitionedAt: row.latestTransitionedAt,
        });

        return {
          assertionId: row.assertionId,
          ...lifecycle,
          revokedAt: row.revokedAt,
        };
      }),
    );
  }

  return states;
};

export const recordAssertionLifecycleTransition = async (
  db: SqlDatabase,
  input: RecordAssertionLifecycleTransitionInput,
): Promise<RecordAssertionLifecycleTransitionResult> => {
  const transitionedAtMs = Date.parse(input.transitionedAt);

  if (!Number.isFinite(transitionedAtMs)) {
    throw new Error("transitionedAt must be a valid ISO timestamp");
  }

  if (!ASSERTION_LIFECYCLE_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported assertion lifecycle reason code: ${input.reasonCode}`);
  }

  if (input.transitionSource === "manual" && input.actorUserId === undefined) {
    throw new Error("Manual lifecycle transitions require actorUserId");
  }

  if (input.transitionSource === "automation" && input.actorUserId !== undefined) {
    throw new Error("Automated lifecycle transitions must not set actorUserId");
  }

  const assertion = await findAssertionById(db, input.tenantId, input.assertionId);

  if (assertion === null) {
    throw new Error(`Assertion ${input.assertionId} not found for tenant ${input.tenantId}`);
  }

  const latestEvent = await findLatestAssertionLifecycleEvent(
    db,
    input.tenantId,
    input.assertionId,
  );
  const current = assertionLifecycleStateFromRecords({
    assertion,
    latestEvent,
  });

  if (current.state === input.toState) {
    return {
      status: "already_in_state",
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `assertion is already in ${current.state} state`,
    };
  }

  const allowedTransitions = ASSERTION_LIFECYCLE_ALLOWED_TRANSITIONS[current.state];

  if (!allowedTransitions.has(input.toState)) {
    return {
      status: "invalid_transition",
      fromState: current.state,
      toState: input.toState,
      currentState: current.state,
      event: null,
      message: `transition from ${current.state} to ${input.toState} is not allowed`,
    };
  }

  const normalizedReason = input.reason?.trim();
  const reason =
    normalizedReason === undefined || normalizedReason.length === 0 ? null : normalizedReason;
  let effectiveTransitionedAt = input.transitionedAt;

  if (input.toState === "revoked") {
    const revocationResult = await recordAssertionRevocation(db, {
      tenantId: input.tenantId,
      assertionId: input.assertionId,
      revocationId: createPrefixedId("rev"),
      reason: reason ?? input.reasonCode,
      idempotencyKey: createPrefixedId("idem"),
      ...(input.actorUserId === undefined ? {} : { revokedByUserId: input.actorUserId }),
      revokedAt: input.transitionedAt,
    });

    if (revocationResult.status === "already_revoked") {
      return {
        status: "already_in_state",
        fromState: current.state,
        toState: input.toState,
        currentState: "revoked",
        event: null,
        message: "assertion is already in revoked state",
      };
    }

    effectiveTransitionedAt = revocationResult.revokedAt;
  }

  const eventId = createPrefixedId("ale");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO assertion_lifecycle_events (
          id,
          tenant_id,
          assertion_id,
          from_state,
          to_state,
          reason_code,
          reason,
          transition_source,
          actor_user_id,
          transitioned_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.assertionId,
        current.state,
        input.toState,
        input.reasonCode,
        reason,
        input.transitionSource,
        input.actorUserId ?? null,
        effectiveTransitionedAt,
        effectiveTransitionedAt,
      )
      .run();

  await insertStatement();

  await db
    .prepare(
      `
      UPDATE assertions
      SET updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(effectiveTransitionedAt, input.tenantId, input.assertionId)
    .run();

  const event = await findAssertionLifecycleEventById(db, eventId);

  if (event === null) {
    throw new Error(`Unable to load assertion lifecycle event ${eventId} after insert`);
  }

  return {
    status: "transitioned",
    fromState: current.state,
    toState: input.toState,
    currentState: input.toState,
    event,
    message: null,
  };
};
