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
