/** Assertion snapshot columns, including explicit preservation state. */
export const assertionAchievementSnapshotSelectSql = `
  assertions.achievement_snapshot_json AS achievementSnapshotJson,
  assertions.achievement_snapshot_status AS achievementSnapshotStatus
`;

/** Complete assertion-record projection used by direct assertion reads. */
export const assertionRecordSelectSql = `
  assertions.id,
  assertions.tenant_id AS tenantId,
  assertions.public_id AS publicId,
  assertions.learner_profile_id AS learnerProfileId,
  assertions.badge_template_id AS badgeTemplateId,
  ${assertionAchievementSnapshotSelectSql},
  assertions.recipient_identity AS recipientIdentity,
  assertions.recipient_identity_type AS recipientIdentityType,
  assertions.vc_r2_key AS vcR2Key,
  assertions.status_list_index AS statusListIndex,
  assertions.idempotency_key AS idempotencyKey,
  assertions.issued_at AS issuedAt,
  assertions.issued_by_user_id AS issuedByUserId,
  assertions.revoked_at AS revokedAt,
  assertions.created_at AS createdAt,
  assertions.updated_at AS updatedAt
`;
