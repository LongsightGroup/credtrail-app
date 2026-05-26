import { createPrefixedId } from "./shared-helpers";
import type { SqlDatabase } from "./tenant-scope";
import { normalizeEmail } from "./users";

export interface LearnerIdentityLinkProofRecord {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: "email";
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

export interface CreateLearnerIdentityLinkProofInput {
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: "email";
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
}
interface LearnerIdentityLinkProofRow {
  id: string;
  tenantId: string;
  learnerProfileId: string;
  requestedByUserId: string;
  identityType: "email";
  identityValue: string;
  tokenHash: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}
export const createLearnerIdentityLinkProof = async (
  db: SqlDatabase,
  input: CreateLearnerIdentityLinkProofInput,
): Promise<LearnerIdentityLinkProofRecord> => {
  const id = createPrefixedId("lip");
  const createdAt = new Date().toISOString();
  const identityValue = normalizeEmail(input.identityValue);

  await db
    .prepare(
      `
      INSERT INTO learner_identity_link_proofs (
        id,
        tenant_id,
        learner_profile_id,
        requested_by_user_id,
        identity_type,
        identity_value,
        token_hash,
        expires_at,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.learnerProfileId,
      input.requestedByUserId,
      input.identityType,
      identityValue,
      input.tokenHash,
      input.expiresAt,
      createdAt,
    )
    .run();

  return {
    id,
    tenantId: input.tenantId,
    learnerProfileId: input.learnerProfileId,
    requestedByUserId: input.requestedByUserId,
    identityType: input.identityType,
    identityValue,
    tokenHash: input.tokenHash,
    expiresAt: input.expiresAt,
    usedAt: null,
    createdAt,
  };
};

export const findLearnerIdentityLinkProofByHash = async (
  db: SqlDatabase,
  tokenHash: string,
): Promise<LearnerIdentityLinkProofRecord | null> => {
  const proof = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        learner_profile_id AS learnerProfileId,
        requested_by_user_id AS requestedByUserId,
        identity_type AS identityType,
        identity_value AS identityValue,
        token_hash AS tokenHash,
        expires_at AS expiresAt,
        used_at AS usedAt,
        created_at AS createdAt
      FROM learner_identity_link_proofs
      WHERE token_hash = ?
      LIMIT 1
    `,
    )
    .bind(tokenHash)
    .first<LearnerIdentityLinkProofRow>();

  return proof;
};

export const markLearnerIdentityLinkProofUsed = async (
  db: SqlDatabase,
  proofId: string,
  usedAt: string,
): Promise<void> => {
  await db
    .prepare(
      `
      UPDATE learner_identity_link_proofs
      SET used_at = ?
      WHERE id = ?
        AND used_at IS NULL
    `,
    )
    .bind(usedAt, proofId)
    .run();
};

export const isLearnerIdentityLinkProofValid = (
  proof: LearnerIdentityLinkProofRecord,
  nowIso: string,
): boolean => {
  if (proof.usedAt !== null) {
    return false;
  }

  const expiryMs = Date.parse(proof.expiresAt);
  const nowMs = Date.parse(nowIso);

  if (!Number.isFinite(expiryMs) || !Number.isFinite(nowMs)) {
    return false;
  }

  return expiryMs > nowMs;
};
