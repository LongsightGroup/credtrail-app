import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import type {
  IssueBadgeQueueJob,
  IssueBadgeRequest,
  RevokeBadgeQueueJob,
  RevokeBadgeRequest,
} from "@credtrail/validation";
import {
  badgeAchievementSnapshotFromTemplate,
  resolveIssuableBadgeAchievementSnapshot,
  type IssuableBadgeArtworkFailure,
} from "../badges/badge-achievement-snapshot";
import { issueBadgeQueueJobFromRequest, revokeBadgeQueueJobFromRequest } from "./job-builders";
import {
  replayIssueBadgeQueueMessage,
  replayRevokeBadgeQueueMessage,
} from "./ingress-replay";
import type { QueueIngressCommandStore } from "./ingress-store";

/** Queue response reconstructed from or persisted for an issuance command. */
export interface IssueBadgeQueueEnvelope {
  readonly assertionId: string;
  readonly job: IssueBadgeQueueJob;
}

/** Queue response reconstructed from or persisted for a revocation command. */
export interface RevokeBadgeQueueEnvelope {
  readonly revocationId: string;
  readonly job: RevokeBadgeQueueJob;
}

/** Typed result of accepting an issuance command at the queue boundary. */
export type IssueQueueIngressResult =
  | { readonly status: "queued"; readonly envelope: IssueBadgeQueueEnvelope }
  | { readonly status: "idempotency_conflict" }
  | { readonly status: "template_not_found" }
  | { readonly status: "template_archived" }
  | { readonly status: "artwork_failure"; readonly failure: IssuableBadgeArtworkFailure };

/** Typed result of accepting a revocation command at the queue boundary. */
export type RevokeQueueIngressResult =
  | { readonly status: "queued"; readonly envelope: RevokeBadgeQueueEnvelope }
  | { readonly status: "idempotency_conflict" };

const existingIssueResult = async (input: {
  readonly store: QueueIngressCommandStore;
  readonly request: IssueBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): Promise<IssueQueueIngressResult | null> => {
  if (input.request.idempotencyKey === undefined) {
    return null;
  }

  const message = await input.store.findByIdempotencyKey({
    tenantId: input.request.tenantId,
    jobType: "issue_badge",
    idempotencyKey: input.request.idempotencyKey,
  });

  if (message === null) {
    return null;
  }

  const replay = replayIssueBadgeQueueMessage({
    message,
    request: input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });

  return replay.status === "matched"
    ? { status: "queued", envelope: replay.envelope }
    : { status: "idempotency_conflict" };
};

const existingRevokeResult = async (input: {
  readonly store: QueueIngressCommandStore;
  readonly request: RevokeBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): Promise<RevokeQueueIngressResult | null> => {
  if (input.request.idempotencyKey === undefined) {
    return null;
  }

  const message = await input.store.findByIdempotencyKey({
    tenantId: input.request.tenantId,
    jobType: "revoke_badge",
    idempotencyKey: input.request.idempotencyKey,
  });

  if (message === null) {
    return null;
  }

  const replay = replayRevokeBadgeQueueMessage({
    message,
    request: input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });

  return replay.status === "matched"
    ? { status: "queued", envelope: replay.envelope }
    : { status: "idempotency_conflict" };
};

/** Validates, snapshots, and atomically persists or replays one issuance command. */
export const issueQueueIngressCommand = async (input: {
  readonly store: QueueIngressCommandStore;
  readonly artworkStore: ImmutableCredentialStore;
  readonly publicAppOrigin: string;
  readonly request: IssueBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): Promise<IssueQueueIngressResult> => {
  const existing = await existingIssueResult(input);

  if (existing !== null) {
    return existing;
  }

  const template = await input.store.findBadgeTemplateById(
    input.request.tenantId,
    input.request.badgeTemplateId,
  );

  if (template === null) {
    return { status: "template_not_found" };
  }

  if (template.isArchived) {
    return { status: "template_archived" };
  }

  const achievement = await resolveIssuableBadgeAchievementSnapshot({
    store: input.artworkStore,
    publicAppOrigin: input.publicAppOrigin,
    tenantId: input.request.tenantId,
    snapshot: badgeAchievementSnapshotFromTemplate(template),
  });

  if (achievement.status !== "resolved") {
    return { status: "artwork_failure", failure: achievement };
  }

  const proposed = issueBadgeQueueJobFromRequest({
    ...input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
    achievementSource: {
      kind: "template_snapshot",
      snapshot: achievement.snapshot,
      provenance: { source: "programmatic" },
    },
  });
  const message = await input.store.enqueueOrReplay({
    tenantId: proposed.job.tenantId,
    jobType: proposed.job.jobType,
    payload: proposed.job.payload,
    idempotencyKey: proposed.job.idempotencyKey,
  });
  const replay = replayIssueBadgeQueueMessage({
    message,
    request: input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });

  return replay.status === "matched"
    ? { status: "queued", envelope: replay.envelope }
    : { status: "idempotency_conflict" };
};

/** Atomically persists or replays one revocation command. */
export const revokeQueueIngressCommand = async (input: {
  readonly store: QueueIngressCommandStore;
  readonly request: RevokeBadgeRequest;
  readonly requestedByUserId?: string | undefined;
}): Promise<RevokeQueueIngressResult> => {
  const existing = await existingRevokeResult(input);

  if (existing !== null) {
    return existing;
  }

  const proposed = revokeBadgeQueueJobFromRequest({
    ...input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });
  const message = await input.store.enqueueOrReplay({
    tenantId: proposed.job.tenantId,
    jobType: proposed.job.jobType,
    payload: proposed.job.payload,
    idempotencyKey: proposed.job.idempotencyKey,
  });
  const replay = replayRevokeBadgeQueueMessage({
    message,
    request: input.request,
    ...(input.requestedByUserId === undefined
      ? {}
      : { requestedByUserId: input.requestedByUserId }),
  });

  return replay.status === "matched"
    ? { status: "queued", envelope: replay.envelope }
    : { status: "idempotency_conflict" };
};
