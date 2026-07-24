/** Stable formal rule and version identities derived from one builder draft identity. */
export interface BadgeIssuanceRuleIdentity {
  readonly ruleId: string;
  readonly versionId: string;
}

const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

/** Maps a tenant-scoped builder draft ID to retry-stable formal resource identities. */
export const badgeIssuanceRuleIdentityForBuilderDraft = async (
  tenantId: string,
  builderDraftId: string,
): Promise<BadgeIssuanceRuleIdentity> => {
  if (!builderDraftId.startsWith("brd_") || builderDraftId.length <= "brd_".length) {
    throw new Error(`Invalid badge rule builder draft ID "${builderDraftId}"`);
  }

  const identityBytes = new TextEncoder().encode(`${tenantId}\u0000${builderDraftId}`);
  const identityDigest = await crypto.subtle.digest("SHA-256", identityBytes);
  const identitySuffix = bytesToHex(new Uint8Array(identityDigest));
  return {
    ruleId: `brl_${identitySuffix}`,
    versionId: `brv_${identitySuffix}`,
  };
};
