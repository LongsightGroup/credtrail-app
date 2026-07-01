const LTI_PROTOCOL_SECRET_REDACTION_LIMIT = 500;
const LTI_PROTOCOL_SECRET_PATTERNS = [/(id_token=)[^&\s,)"']+/gi, /(state=)[^&\s,)"']+/gi] as const;

/**
 * Redacts LTI protocol secrets from free-text error or log messages.
 */
export const redactLtiProtocolSecrets = (value: string): string => {
  let redacted = value;

  for (const pattern of LTI_PROTOCOL_SECRET_PATTERNS) {
    redacted = redacted.replace(pattern, "$1[redacted]");
  }

  return redacted.slice(0, LTI_PROTOCOL_SECRET_REDACTION_LIMIT);
};
