import { Hono } from "hono";
import { afterEach, expect, it } from "vitest";
import {
  cleanupTestResources,
  createBadgeRuleIntegrationFixture,
  createTestPostgresDatabase,
  describeDbIntegration,
  seedAssertion,
} from "../../../../packages/db/src/postgres-test-support";
import type { ImmutableCredentialStore } from "@credtrail/core-domain";
import type { AppBindings, AppEnv } from "../app/types";
import { createPublicBadgeTestRenderers } from "../test-support/public-badge-renderers";
import { loadPublicBadgeViewModel } from "../badges/public-badge-model";
import { publicBadgeSummaryPayload } from "../badges/public-badge-summary-payload";
import { asNonEmptyString } from "../utils/value-parsers";
import { formatIsoTimestamp } from "../utils/display-format";
import { registerPublicBadgeRoutes } from "./public-badge-routes";
import { registerAppPageRenderer } from "../ui/render-page";

const tenantIds: string[] = [];
const userIds: string[] = [];
afterEach(async () => {
  await cleanupTestResources(createTestPostgresDatabase(), { tenantIds, userIds });
  tenantIds.length = 0;
  userIds.length = 0;
});

describeDbIntegration("public institution collections and wallet sharing", () => {
  it("renders each institution's name safely and keeps public collection links scoped", async () => {
    const first = await createBadgeRuleIntegrationFixture();
    const second = await createBadgeRuleIntegrationFixture();
    tenantIds.push(first.tenantId, second.tenantId);
    userIds.push(first.userId, second.userId);
    const db = first.db;
    const names = ['North & <script>alert("unsafe")</script> University', "South College"];
    for (const [index, fixture] of [first, second].entries()) {
      await db
        .prepare("UPDATE tenants SET display_name = ? WHERE id = ?")
        .bind(names[index], fixture.tenantId)
        .run();
    }
    const store: ImmutableCredentialStore = {
      head: async () => null,
      get: async () => null,
      put: async () => null,
      delete: async () => undefined,
    };
    const app = new Hono<AppEnv>();
    registerAppPageRenderer(app);
    registerPublicBadgeRoutes({
      app,
      resolveDatabase: () => db,
      loadPublicBadgeViewModel,
      ...createPublicBadgeTestRenderers(),
      publicBadgeSummaryPayload: (requestUrl, model) =>
        publicBadgeSummaryPayload({ requestUrl, model, formatIsoTimestamp }),
      asNonEmptyString,
      SAKAI_SHOWCASE_TENANT_ID: "sakai",
      SAKAI_SHOWCASE_TEMPLATE_ID: "sakai-default",
    });
    const env: AppBindings = {
      APP_ENV: "test",
      PLATFORM_DOMAIN: "credtrail.org",
      PUBLIC_APP_ORIGIN: "https://credtrail.org",
      BADGE_OBJECTS: store,
    };
    for (const suffix of ["", "/criteria"]) {
      const responses = await Promise.all(
        [first, second].map(async (fixture) =>
          app.request(`/showcase/${fixture.tenantId}${suffix}`, undefined, env),
        ),
      );
      const [north, south] = await Promise.all(responses.map((response) => response.text()));
      expect(responses.map((response) => response.status)).toEqual([200, 200]);
      expect(north).toContain("North &amp; &lt;script&gt;");
      expect(north).not.toContain("<script>alert");
      expect(north).not.toContain("South College");
      expect(south).toContain('property="og:site_name" content="South College"');
      expect(south).not.toContain("North");
      expect(south).toContain(`https://credtrail.org/showcase/${second.tenantId}${suffix}`);
      expect(south).not.toContain(first.tenantId);
      expect(
        (await app.request(`/showcase/missing-institution${suffix}`, undefined, env)).status,
      ).toBe(404);
    }
    await db
      .prepare("UPDATE tenants SET display_name = ' ' WHERE id = ?")
      .bind(first.tenantId)
      .run();
    expect((await app.request(`/showcase/${first.tenantId}`, undefined, env)).status).toBe(404);

    // The invitation rendered on the public badge uses the same canonical VC-API exchange.
    const publicId = crypto.randomUUID();
    await seedAssertion(db, {
      tenantId: second.tenantId,
      badgeTemplateId: second.badgeTemplateId,
      recipientIdentity: "learner@example.edu",
      issuedAt: "2026-10-07T00:00:00.000Z",
      publicId,
    });
    const credential = JSON.stringify({
      issuer: { id: "did:web:example.edu", name: "South College" },
      credentialSubject: {
        id: "mailto:learner@example.edu",
        achievement: {
          name: "Community participation",
          description: "Attended the community event.",
        },
      },
    });
    const response = await app.request(`/badges/${publicId}`, undefined, {
      ...env,
      BADGE_OBJECTS: {
        ...store,
        get: async () => ({ size: credential.length, text: async () => credential }),
      },
    });
    expect(response.status).toBe(200);
    const html = await response.text();
    const encodedUrl = html.match(/href="(https:\/\/lcw\.app\/request[^"]+)"/u)?.[1];
    if (encodedUrl === undefined) throw new Error("Missing wallet invitation");
    const walletUrl = new URL(encodedUrl.replaceAll("&amp;", "&"));
    expect(JSON.parse(walletUrl.searchParams.get("request") ?? "null")).toEqual({
      credentialRequestOrigin: "https://credtrail.org",
      protocols: { vcapi: `https://credtrail.org/credentials/v1/dcc/exchanges/${publicId}` },
    });
  });
});
