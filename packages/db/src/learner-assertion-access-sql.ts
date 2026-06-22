export const assertionBadgeTemplateJoinSql = `
  FROM assertions
  INNER JOIN badge_templates
    ON badge_templates.tenant_id = assertions.tenant_id
    AND badge_templates.id = assertions.badge_template_id
`;

export const buildLegacyLearnerEmailAccessFilter = (): string => {
  return `
    assertions.recipient_identity_type = 'email'
    AND LOWER(assertions.recipient_identity) = ?
  `;
};

export const buildLearnerProfileOrEmailAccessFilter = (emailAliases: readonly string[]): string => {
  if (emailAliases.length === 0) {
    return "assertions.learner_profile_id = ?";
  }

  const emailPlaceholders = emailAliases.map(() => "?").join(", ");

  return `(
    assertions.learner_profile_id = ?
    OR (
      assertions.recipient_identity_type = 'email'
      AND LOWER(assertions.recipient_identity) IN (${emailPlaceholders})
    )
  )`;
};

export const bindLearnerProfileOrEmailAccessParams = (
  learnerProfileId: string,
  emailAliases: readonly string[],
): unknown[] => {
  return [learnerProfileId, ...emailAliases];
};
