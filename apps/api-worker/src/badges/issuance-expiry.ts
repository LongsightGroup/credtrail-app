/** A caller-supplied expiry that cannot produce a valid credential at issuance time. */
export interface IssuanceExpiryFailure {
  readonly code: "invalid_expiry";
  readonly error: string;
}

/** Checks a parsed optional expiry against the issuance instant supplied by the caller. */
export const issuanceExpiryFailure = (
  validUntil: string | undefined,
  issuedAt: string,
): IssuanceExpiryFailure | null => {
  if (validUntil === undefined || Date.parse(validUntil) > Date.parse(issuedAt)) return null;
  return {
    code: "invalid_expiry",
    error: "Valid until must be later than the issue date.",
  };
};
