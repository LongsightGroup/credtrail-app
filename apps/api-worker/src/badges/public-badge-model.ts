import {
  getImmutableCredentialObject,
  splitTenantScopedId,
  type JsonObject,
} from '@credtrail/core-domain';
import {
  findAssertionById,
  findAssertionByPublicId,
  findLearnerProfileById,
  type AssertionRecord,
  type SqlDatabase,
} from '@credtrail/db';

export interface VerificationViewModel {
  assertion: AssertionRecord;
  credential: JsonObject;
  recipientDisplayName: string | null;
}

export type VerificationLookupResult =
  | {
      status: 'ok';
      value: VerificationViewModel;
    }
  | {
      status: 'invalid_id' | 'not_found';
    };

export type PublicBadgeLookupResult =
  | {
      status: 'ok';
      value: VerificationViewModel;
    }
  | {
      status: 'redirect';
      canonicalPath: string;
    }
  | {
      status: 'not_found';
    };

export const parseTenantScopedCredentialId = (
  credentialId: string,
): { tenantId: string; resourceId: string } | null => {
  try {
    const parsed = splitTenantScopedId(credentialId);

    if (parsed.tenantId.trim().length === 0 || parsed.resourceId.trim().length === 0) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
};

export const assertionBelongsToTenant = (tenantId: string, assertionId: string): boolean => {
  const scoped = parseTenantScopedCredentialId(assertionId);
  return scoped !== null && scoped.tenantId === tenantId;
};

export const publicBadgePermalinkSegment = (assertion: AssertionRecord): string => {
  return assertion.publicId ?? assertion.id;
};

export const publicBadgePathForAssertion = (assertion: AssertionRecord): string => {
  return `/badges/${encodeURIComponent(publicBadgePermalinkSegment(assertion))}`;
};

export const loadCredentialForAssertion = async (
  store: R2Bucket,
  assertion: AssertionRecord,
): Promise<JsonObject> => {
  const credential = await getImmutableCredentialObject(store, {
    tenantId: assertion.tenantId,
    assertionId: assertion.id,
  });

  if (credential === null) {
    throw new Error(`Assertion "${assertion.id}" is missing its immutable credential object`);
  }

  return credential;
};

const loadRecipientDisplayNameForAssertion = async (
  db: SqlDatabase,
  assertion: AssertionRecord,
): Promise<string | null> => {
  if (assertion.learnerProfileId === null) {
    return null;
  }

  const learnerProfile = await findLearnerProfileById(
    db,
    assertion.tenantId,
    assertion.learnerProfileId,
  );
  return learnerProfile?.displayName ?? null;
};

export const loadVerificationViewModel = async (
  db: SqlDatabase,
  store: R2Bucket,
  credentialId: string,
): Promise<VerificationLookupResult> => {
  const tenantScopedCredentialId = parseTenantScopedCredentialId(credentialId);

  if (tenantScopedCredentialId === null) {
    return {
      status: 'invalid_id',
    };
  }

  const assertion = await findAssertionById(db, tenantScopedCredentialId.tenantId, credentialId);

  if (assertion === null) {
    return {
      status: 'not_found',
    };
  }

  const credential = await loadCredentialForAssertion(store, assertion);

  return {
    status: 'ok',
    value: {
      assertion,
      credential,
      recipientDisplayName: null,
    },
  };
};

export const loadPublicBadgeViewModel = async (
  db: SqlDatabase,
  store: R2Bucket,
  badgeIdentifier: string,
): Promise<PublicBadgeLookupResult> => {
  const trimmedIdentifier = badgeIdentifier.trim();

  if (trimmedIdentifier.length === 0) {
    return {
      status: 'not_found',
    };
  }

  const assertionByPublicId = await findAssertionByPublicId(db, trimmedIdentifier);

  if (assertionByPublicId !== null) {
    const credential = await loadCredentialForAssertion(store, assertionByPublicId);
    const recipientDisplayName = await loadRecipientDisplayNameForAssertion(
      db,
      assertionByPublicId,
    );

    return {
      status: 'ok',
      value: {
        assertion: assertionByPublicId,
        credential,
        recipientDisplayName,
      },
    };
  }

  const tenantScopedCredentialId = parseTenantScopedCredentialId(trimmedIdentifier);

  if (tenantScopedCredentialId === null) {
    return {
      status: 'not_found',
    };
  }

  const assertion = await findAssertionById(
    db,
    tenantScopedCredentialId.tenantId,
    trimmedIdentifier,
  );

  if (assertion === null) {
    return {
      status: 'not_found',
    };
  }

  if (publicBadgePermalinkSegment(assertion) === trimmedIdentifier) {
    const credential = await loadCredentialForAssertion(store, assertion);
    const recipientDisplayName = await loadRecipientDisplayNameForAssertion(db, assertion);

    return {
      status: 'ok',
      value: {
        assertion,
        credential,
        recipientDisplayName,
      },
    };
  }

  return {
    status: 'redirect',
    canonicalPath: publicBadgePathForAssertion(assertion),
  };
};
