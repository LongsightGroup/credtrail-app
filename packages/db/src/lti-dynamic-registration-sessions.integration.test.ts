import { expect, it } from "vitest";

import {
  consumeLtiDynamicRegistrationSession,
  upsertLtiDynamicRegistrationSession,
} from "./lti.js";
import {
  cleanupTestResources,
  createTestTenantFixture,
  describeDbIntegration,
  selectCount,
  uniqueTestId,
} from "./postgres-test-support.js";

const NOW_ISO = "2026-09-02T14:00:00.000Z";
const FUTURE_ISO = "2026-09-02T15:00:00.000Z";

describeDbIntegration("LTI dynamic-registration session consumption with Postgres", () => {
  it("returns an unexpired session to only one concurrent consumer", async () => {
    const fixture = await createTestTenantFixture();
    const sessionId = uniqueTestId("lti_registration_session");

    try {
      await upsertLtiDynamicRegistrationSession(fixture.db, {
        tenantId: fixture.tenantId,
        id: sessionId,
        dataJson: JSON.stringify({ registrationToken: "test-token" }),
        expiresAt: FUTURE_ISO,
      });

      const results = await Promise.all([
        consumeLtiDynamicRegistrationSession(fixture.db, {
          tenantId: fixture.tenantId,
          sessionId,
          nowIso: NOW_ISO,
        }),
        consumeLtiDynamicRegistrationSession(fixture.db, {
          tenantId: fixture.tenantId,
          sessionId,
          nowIso: NOW_ISO,
        }),
      ]);
      const consumed = results.filter((result) => result !== null);

      expect(consumed).toHaveLength(1);
      expect(consumed[0]).toMatchObject({
        tenantId: fixture.tenantId,
        id: sessionId,
        dataJson: JSON.stringify({ registrationToken: "test-token" }),
        expiresAt: FUTURE_ISO,
      });
      await expect(
        consumeLtiDynamicRegistrationSession(fixture.db, {
          tenantId: fixture.tenantId,
          sessionId,
          nowIso: NOW_ISO,
        }),
      ).resolves.toBeNull();
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("does not consume an expired session", async () => {
    const fixture = await createTestTenantFixture();
    const sessionId = uniqueTestId("lti_registration_session");

    try {
      await upsertLtiDynamicRegistrationSession(fixture.db, {
        tenantId: fixture.tenantId,
        id: sessionId,
        dataJson: "{}",
        expiresAt: NOW_ISO,
      });

      await expect(
        consumeLtiDynamicRegistrationSession(fixture.db, {
          tenantId: fixture.tenantId,
          sessionId,
          nowIso: NOW_ISO,
        }),
      ).resolves.toBeNull();
      await expect(
        selectCount(
          fixture.db,
          "SELECT COUNT(*) AS totalCount FROM lti_dynamic_registration_sessions WHERE tenant_id = ? AND id = ?",
          [fixture.tenantId, sessionId],
        ),
      ).resolves.toBe(1);
    } finally {
      await cleanupTestResources(fixture.db, { tenantIds: [fixture.tenantId] });
    }
  });

  it("keeps same-ID sessions isolated by tenant", async () => {
    const firstFixture = await createTestTenantFixture();
    const secondFixture = await createTestTenantFixture();
    const sessionId = uniqueTestId("lti_registration_session");

    try {
      await Promise.all([
        upsertLtiDynamicRegistrationSession(firstFixture.db, {
          tenantId: firstFixture.tenantId,
          id: sessionId,
          dataJson: JSON.stringify({ tenant: "first" }),
          expiresAt: FUTURE_ISO,
        }),
        upsertLtiDynamicRegistrationSession(secondFixture.db, {
          tenantId: secondFixture.tenantId,
          id: sessionId,
          dataJson: JSON.stringify({ tenant: "second" }),
          expiresAt: FUTURE_ISO,
        }),
      ]);

      const first = await consumeLtiDynamicRegistrationSession(firstFixture.db, {
        tenantId: firstFixture.tenantId,
        sessionId,
        nowIso: NOW_ISO,
      });
      const second = await consumeLtiDynamicRegistrationSession(secondFixture.db, {
        tenantId: secondFixture.tenantId,
        sessionId,
        nowIso: NOW_ISO,
      });

      expect(first?.dataJson).toBe(JSON.stringify({ tenant: "first" }));
      expect(second?.dataJson).toBe(JSON.stringify({ tenant: "second" }));
    } finally {
      await cleanupTestResources(firstFixture.db, {
        tenantIds: [firstFixture.tenantId, secondFixture.tenantId],
      });
    }
  });
});
