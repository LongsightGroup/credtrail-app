import {
  findTenantLmsConnectionByLtiRegistration,
  upsertTenantLmsUserIdentity,
  type SqlDatabase,
} from "@credtrail/db";

/** Verified launch identity required to authorize an instructor's LMS course actions. */
export interface LinkInstructorLmsIdentityInput {
  readonly tenantId: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly deploymentId: string;
  readonly userId: string;
  readonly providerUserId: string;
}

/** Typed persistence failure for instructor LMS identity linking. */
export interface InstructorLmsIdentityLinkFailure {
  readonly _tag: "InstructorLmsIdentityLinkFailure";
  readonly message: "CredTrail could not verify your LMS course access";
  readonly cause: unknown;
}

/** Result of linking an instructor to the LMS connection for a verified launch. */
export type LinkInstructorLmsIdentityResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly error: InstructorLmsIdentityLinkFailure };

/**
 * Records the verified LMS subject used to authorize an instructor's course-scoped actions.
 */
export const linkInstructorLmsIdentity = async (
  db: SqlDatabase,
  input: LinkInstructorLmsIdentityInput,
): Promise<LinkInstructorLmsIdentityResult> => {
  try {
    const connection = await findTenantLmsConnectionByLtiRegistration(db, {
      tenantId: input.tenantId,
      issuer: input.issuer,
      clientId: input.clientId,
      deploymentId: input.deploymentId,
    });

    if (connection === null) {
      return { ok: true };
    }

    await upsertTenantLmsUserIdentity(db, {
      tenantId: input.tenantId,
      connectionId: connection.id,
      userId: input.userId,
      providerUserId: input.providerUserId,
    });

    return { ok: true };
  } catch (cause: unknown) {
    return {
      ok: false,
      error: {
        _tag: "InstructorLmsIdentityLinkFailure",
        message: "CredTrail could not verify your LMS course access",
        cause,
      },
    };
  }
};
