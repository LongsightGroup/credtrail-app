import { expect, it } from "vitest";

import {
  createAuthIdentityLink,
  findAuthIdentityLinkByAuthUserId,
  findAuthIdentityLinkByCredtrailUserId,
  findUserByEmail,
  upsertUserByEmail,
} from "./index";
import {
  cleanupTestResources,
  createTestPostgresDatabase,
  describeDbIntegration,
  uniqueTestId,
} from "./postgres-test-support";

describeDbIntegration("auth identity links", () => {
  it("persists and resolves Better Auth links by auth system and auth user id", async () => {
    const db = createTestPostgresDatabase();
    const email = `${uniqueTestId("student")}@example.edu`;
    const authUserId = uniqueTestId("ba_usr");
    const authAccountId = uniqueTestId("ba_account");
    const user = await upsertUserByEmail(db, ` ${email.toUpperCase()} `);

    try {
      const link = await createAuthIdentityLink(db, {
        authSystem: "better_auth",
        authUserId,
        authAccountId,
        credtrailUserId: user.id,
        emailSnapshot: email,
      });

      const resolvedByAuthUser = await findAuthIdentityLinkByAuthUserId(
        db,
        "better_auth",
        authUserId,
      );
      const resolvedByCredtrailUser = await findAuthIdentityLinkByCredtrailUserId(
        db,
        "better_auth",
        user.id,
      );
      const resolvedUser = await findUserByEmail(db, email);

      expect(resolvedByAuthUser).toEqual(link);
      expect(resolvedByCredtrailUser).toEqual(link);
      expect(resolvedUser).toEqual(user);
      expect(link.emailSnapshot).toBe(email);
    } finally {
      await cleanupTestResources(db, {
        userIds: [user.id],
      });
    }
  });
});
