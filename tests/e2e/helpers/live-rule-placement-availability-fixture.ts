import {
  createTenantOrgUnit,
  ensureInstitutionOrgUnitForTenant,
  upsertTenant,
  upsertLtiIssuerRegistration,
  upsertTenantLmsConnection,
  upsertTenantMembershipRole,
  upsertUserByEmail,
  type SqlDatabase,
} from "@credtrail/db";
import { createPostgresDatabase } from "@credtrail/db/postgres";
import { managedBadgeTemplateImagePath } from "@credtrail/validation";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

import { createTestBadgeIssuanceRule } from "../../../packages/db/src/badge-issuance-rule-test-fixtures";
import { loadLocalDevEnv, requireEnv } from "../../../scripts/local-dev-env.mjs";

export interface LiveRulePlacementAvailabilityFixture {
  readonly tenantId: string;
  readonly adminEmail: string;
  readonly ruleName: string;
  readonly departmentId: string;
  readonly departmentName: string;
  readonly courseTitle: string;
  readonly secondCourseTitle: string;
  readonly rulesPath: string;
  readonly initialRuleState: LiveRuleState;
  readonly readRuleState: () => Promise<LiveRuleState>;
  readonly ltiPlatform: LiveLtiPlatform;
  readonly readPlacementContexts: () => Promise<readonly string[]>;
  readonly dispose: () => Promise<void>;
}

export interface LiveLtiContentItem {
  readonly title: string;
  readonly url: string;
  readonly custom: {
    readonly badgeTemplateId: string;
    readonly ruleId: string;
  };
}

export interface LiveLtiPlatform {
  readonly issuer: string;
  readonly clientId: string;
  readonly deploymentId: string;
  readonly instructorEmail: string;
  readonly deepLinkReturnUrl: string;
  readonly readContentItem: () => LiveLtiContentItem;
}

export interface LiveRuleState {
  readonly activeVersionId: string | null;
  readonly ruleJson: string;
  readonly versionCount: number;
}

const deleteFixture = async (
  db: SqlDatabase,
  input: { readonly tenantId: string; readonly userId: string },
): Promise<void> => {
  const ltiUsers = await db
    .prepare(
      `
        SELECT DISTINCT user_id AS userId
        FROM tenant_lms_user_identities
        WHERE tenant_id = ?
      `,
    )
    .bind(input.tenantId)
    .all<{ readonly userId: string }>();
  const userIds = [...new Set([input.userId, ...ltiUsers.results.map((entry) => entry.userId)])];
  const authUserIds: string[] = [];

  for (const userId of userIds) {
    const authUsers = await db
      .prepare(
        `
          SELECT auth_user_id AS authUserId
          FROM auth_identity_links
          WHERE credtrail_user_id = ?
        `,
      )
      .bind(userId)
      .all<{ readonly authUserId: string }>();
    authUserIds.push(...authUsers.results.map((entry) => entry.authUserId));
  }

  await db.prepare("DELETE FROM tenants WHERE id = ?").bind(input.tenantId).run();

  for (const userId of userIds) {
    await db.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
  }

  for (const authUserId of authUserIds) {
    await db.prepare("DELETE FROM auth.user WHERE id = ?").bind(authUserId).run();
  }
};

const startMockSakai = async (): Promise<{
  readonly apiBaseUrl: string;
  readonly courseTitle: string;
  readonly secondCourseTitle: string;
  readonly close: () => Promise<void>;
}> => {
  const courses = [
    {
      id: "course-placement-e2e",
      title: "Community Data Capstone",
      type: "course",
      maintainRole: "Instructor",
      shortDescription: "DATA 490",
      published: true,
    },
    {
      id: "course-placement-studio-e2e",
      title: "Community Data Studio",
      type: "course",
      maintainRole: "Instructor",
      shortDescription: "DATA 390",
      published: true,
    },
  ];
  const server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
    const resolvedCourse = courses.find(
      (course) => requestUrl.pathname === `/direct/site/${course.id}.json`,
    );
    const body =
      requestUrl.pathname === "/direct/site.json"
        ? { site_collection: requestUrl.searchParams.has("_start") ? [] : courses }
        : resolvedCourse !== undefined
          ? resolvedCourse
          : { error: `No mock route configured for ${requestUrl.pathname}` };
    const statusCode = "error" in body ? 404 : 200;
    response.writeHead(statusCode, { "content-type": "application/json" });
    response.end(JSON.stringify(body));
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();

  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("Mock Sakai server did not bind to a TCP port");
  }

  return {
    apiBaseUrl: `http://127.0.0.1:${String(address.port)}`,
    courseTitle: courses[0]?.title ?? "Community Data Capstone",
    secondCourseTitle: courses[1]?.title ?? "Community Data Studio",
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
};

const ltiClaim = {
  context: "https://purl.imsglobal.org/spec/lti/claim/context",
  custom: "https://purl.imsglobal.org/spec/lti/claim/custom",
  deepLinkingSettings: "https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings",
  deploymentId: "https://purl.imsglobal.org/spec/lti/claim/deployment_id",
  messageType: "https://purl.imsglobal.org/spec/lti/claim/message_type",
  resourceLink: "https://purl.imsglobal.org/spec/lti/claim/resource_link",
  roles: "https://purl.imsglobal.org/spec/lti/claim/roles",
  targetLinkUri: "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
  version: "https://purl.imsglobal.org/spec/lti/claim/version",
} as const;

const base64Url = (value: string | Uint8Array): string => {
  return Buffer.from(value).toString("base64url");
};

const signPlatformJwt = async (
  privateKey: CryptoKey,
  keyId: string,
  payload: Readonly<Record<string, unknown>>,
): Promise<string> => {
  const headerSegment = base64Url(JSON.stringify({ alg: "RS256", kid: keyId, typ: "JWT" }));
  const payloadSegment = base64Url(JSON.stringify(payload));
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
};

const readRequestBody = async (request: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];

  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }

  return Buffer.concat(chunks).toString("utf8");
};

const respondJson = (response: ServerResponse, body: unknown, statusCode = 200): void => {
  response.writeHead(statusCode, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
};

const requireQuery = (url: URL, name: string): string => {
  const value = url.searchParams.get(name)?.trim() ?? "";

  if (value.length === 0) {
    throw new Error(`Mock LTI authorization request is missing ${name}`);
  }

  return value;
};

const parseRecord = (value: unknown, label: string): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }

  return value as Record<string, unknown>;
};

const requireRecordText = (record: Record<string, unknown>, field: string): string => {
  const value = record[field];

  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`Mock LTI value ${field} must be text`);
  }

  return value;
};

const contentItemFromDeepLinkResponse = (compactJwt: string): LiveLtiContentItem => {
  const payloadSegment = compactJwt.split(".")[1];

  if (payloadSegment === undefined) {
    throw new Error("Deep Linking response is not a compact JWT");
  }

  const payload = parseRecord(
    JSON.parse(Buffer.from(payloadSegment, "base64url").toString("utf8")) as unknown,
    "Deep Linking response",
  );
  const rawItems = payload["https://purl.imsglobal.org/spec/lti-dl/claim/content_items"];

  if (!Array.isArray(rawItems) || rawItems.length !== 1) {
    throw new Error("Deep Linking response must contain exactly one content item");
  }

  const item = parseRecord(rawItems[0], "Deep Linking content item");
  const custom = parseRecord(item.custom, "Deep Linking custom parameters");

  return {
    title: requireRecordText(item, "title"),
    url: requireRecordText(item, "url"),
    custom: {
      badgeTemplateId: requireRecordText(custom, "badgeTemplateId"),
      ruleId: requireRecordText(custom, "ruleId"),
    },
  };
};

interface MockLaunchHint {
  readonly kind: "deep-link" | "resource";
  readonly contextId: string;
  readonly contextTitle: string;
  readonly targetLinkUri: string;
  readonly resourceLinkId?: string | undefined;
  readonly custom?: Readonly<Record<string, string>> | undefined;
}

const parseLaunchHint = (raw: string): MockLaunchHint => {
  const parsed = parseRecord(JSON.parse(raw) as unknown, "LTI message hint");
  const kind = requireRecordText(parsed, "kind");

  if (kind !== "deep-link" && kind !== "resource") {
    throw new Error("LTI message hint has an unsupported kind");
  }

  const customRecord = parsed.custom;
  const custom =
    customRecord === undefined
      ? undefined
      : Object.fromEntries(
          Object.entries(parseRecord(customRecord, "LTI message hint custom parameters")).map(
            ([key, value]) => {
              if (typeof value !== "string") {
                throw new Error(`LTI custom parameter ${key} must be text`);
              }

              return [key, value];
            },
          ),
        );

  return {
    kind,
    contextId: requireRecordText(parsed, "contextId"),
    contextTitle: requireRecordText(parsed, "contextTitle"),
    targetLinkUri: requireRecordText(parsed, "targetLinkUri"),
    ...(parsed.resourceLinkId === undefined
      ? {}
      : { resourceLinkId: requireRecordText(parsed, "resourceLinkId") }),
    ...(custom === undefined ? {} : { custom }),
  };
};

const startMockLtiPlatform = async (
  suffix: string,
): Promise<{
  readonly platform: LiveLtiPlatform;
  readonly authorizationEndpoint: string;
  readonly platformJwksEndpoint: string;
  readonly tokenEndpoint: string;
  readonly close: () => Promise<void>;
}> => {
  const keyId = `platform-key-${suffix}`;
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
    },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const clientId = `lti-client-${suffix}`;
  const deploymentId = `lti-deployment-${suffix}`;
  const instructorEmail = `lti-instructor-${suffix}@example.edu`;
  let issuer = "";
  let capturedContentItem: LiveLtiContentItem | null = null;
  const server = createServer((request, response) => {
    void (async () => {
      const requestUrl = new URL(request.url ?? "/", issuer || "http://127.0.0.1");

      if (requestUrl.pathname === "/jwks") {
        respondJson(response, {
          keys: [{ ...publicJwk, alg: "RS256", kid: keyId, use: "sig" }],
        });
        return;
      }

      if (requestUrl.pathname === "/token") {
        respondJson(response, {
          access_token: "mock-token",
          expires_in: 300,
          token_type: "Bearer",
        });
        return;
      }

      if (requestUrl.pathname === "/deep-link-return" && request.method === "POST") {
        const form = new URLSearchParams(await readRequestBody(request));
        const compactJwt = form.get("JWT");

        if (compactJwt === null) {
          throw new Error("Deep Linking return is missing JWT");
        }

        capturedContentItem = contentItemFromDeepLinkResponse(compactJwt);
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end("<!doctype html><html><body><h1>Content added to course</h1></body></html>");
        return;
      }

      if (requestUrl.pathname !== "/authorize") {
        respondJson(
          response,
          { error: `No mock route configured for ${requestUrl.pathname}` },
          404,
        );
        return;
      }

      const state = requireQuery(requestUrl, "state");
      const nonce = requireQuery(requestUrl, "nonce");
      const redirectUri = requireQuery(requestUrl, "redirect_uri");
      const hint = parseLaunchHint(requireQuery(requestUrl, "lti_message_hint"));
      const nowEpochSeconds = Math.floor(Date.now() / 1000);
      const commonClaims: Record<string, unknown> = {
        iss: issuer,
        sub: "stable-rule-instructor",
        aud: clientId,
        exp: nowEpochSeconds + 300,
        iat: nowEpochSeconds - 5,
        nonce,
        email: instructorEmail,
        name: "Stable Rule Instructor",
        [ltiClaim.deploymentId]: deploymentId,
        [ltiClaim.version]: "1.3.0",
        [ltiClaim.targetLinkUri]: hint.targetLinkUri,
        [ltiClaim.context]: {
          id: hint.contextId,
          label: hint.contextId.toUpperCase(),
          title: hint.contextTitle,
        },
        [ltiClaim.roles]: ["http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor"],
      };
      const payload =
        hint.kind === "deep-link"
          ? {
              ...commonClaims,
              [ltiClaim.messageType]: "LtiDeepLinkingRequest",
              [ltiClaim.deepLinkingSettings]: {
                deep_link_return_url: `${issuer}/deep-link-return`,
                accept_types: ["ltiResourceLink"],
                accept_presentation_document_targets: ["iframe", "window"],
                accept_multiple: false,
                auto_create: false,
                data: `deep-link-data-${suffix}`,
              },
            }
          : {
              ...commonClaims,
              [ltiClaim.messageType]: "LtiResourceLinkRequest",
              [ltiClaim.resourceLink]: {
                id: hint.resourceLinkId ?? `resource-${suffix}`,
                title: "Stable rule badge",
              },
              [ltiClaim.custom]: hint.custom ?? {},
            };
      const idToken = await signPlatformJwt(keyPair.privateKey, keyId, payload);
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end(`<!doctype html>
        <html><body>
          <form id="launch" method="post" action="${redirectUri}">
            <input type="hidden" name="id_token" value="${idToken}">
            <input type="hidden" name="state" value="${state}">
          </form>
          <script>document.getElementById("launch").submit()</script>
        </body></html>`);
    })().catch((error: unknown) => {
      response.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      response.end(error instanceof Error ? error.message : "Mock LTI platform failed");
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();

  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("Mock LTI platform did not bind to a TCP port");
  }

  issuer = `http://127.0.0.1:${String(address.port)}`;
  return {
    platform: {
      issuer,
      clientId,
      deploymentId,
      instructorEmail,
      deepLinkReturnUrl: `${issuer}/deep-link-return`,
      readContentItem: () => {
        if (capturedContentItem === null) {
          throw new Error("Mock LTI platform has not received a content item");
        }

        return capturedContentItem;
      },
    },
    authorizationEndpoint: `${issuer}/authorize`,
    platformJwksEndpoint: `${issuer}/jwks`,
    tokenEndpoint: `${issuer}/token`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) {
            resolve();
          } else {
            reject(error);
          }
        });
      }),
  };
};

/** Creates a disposable tenant and LMS for the live course-availability browser workflow. */
export const createLiveRulePlacementAvailabilityFixture =
  async (): Promise<LiveRulePlacementAvailabilityFixture> => {
    loadLocalDevEnv();
    const db = createPostgresDatabase({
      databaseUrl: requireEnv("DATABASE_URL"),
      connectionMode: "single-use",
    });
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `tenant_e2e_availability_${suffix}`;
    const adminEmail = `availability-admin-${suffix}@example.edu`;
    const badgeTemplateId = `badge_template_e2e_availability_${suffix}`;
    const lmsConnectionId = `lms_e2e_availability_${suffix}`;
    const ruleName = `Course availability ${suffix.slice(0, 8)}`;
    const departmentName = "Applied Data Studies";
    const ruleJson = JSON.stringify({
      conditions: {
        type: "course_completion",
        courseId: "course-placement-e2e",
        minCompletionPercent: 100,
      },
    });
    const mockSakai = await startMockSakai();
    const mockLti = await startMockLtiPlatform(suffix);
    let tenantCreated = false;
    let adminUserId: string | null = null;

    try {
      await upsertTenant(db, {
        id: tenantId,
        slug: `availability-e2e-${suffix}`,
        displayName: "Availability E2E University",
        planTier: "institution",
        issuerDomain: `availability-e2e-${suffix}.issuer.test`,
        didWeb: `did:web:availability-e2e-${suffix}.issuer.test`,
        isActive: true,
      });
      tenantCreated = true;
      const institutionId = await ensureInstitutionOrgUnitForTenant(db, tenantId);
      const admin = await upsertUserByEmail(db, adminEmail);
      adminUserId = admin.id;
      await upsertTenantMembershipRole(db, { tenantId, userId: admin.id, role: "owner" });
      const college = await createTenantOrgUnit(db, {
        tenantId,
        unitType: "college",
        slug: "community-studies",
        displayName: "College of Community Studies",
        parentOrgUnitId: institutionId,
        createdByUserId: admin.id,
      });
      const department = await createTenantOrgUnit(db, {
        tenantId,
        unitType: "department",
        slug: "applied-data-studies",
        displayName: departmentName,
        parentOrgUnitId: college.id,
        createdByUserId: admin.id,
      });
      await db
        .prepare(
          `
          INSERT INTO badge_templates (
            id,
            tenant_id,
            slug,
            title,
            description,
            criteria_uri,
            image_uri,
            created_by_user_id,
            owner_org_unit_id,
            governance_metadata_json
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        )
        .bind(
          badgeTemplateId,
          tenantId,
          `course-availability-${suffix}`,
          "Community Data Badge",
          "Awarded after the governed community data capstone.",
          "https://credtrail.org/criteria/community-data",
          `https://credtrail.org${managedBadgeTemplateImagePath({
            tenantId,
            badgeTemplateId,
            assetId: `asset_${suffix}`,
          })}`,
          admin.id,
          institutionId,
          '{"source":"e2e_test"}',
        )
        .run();
      await upsertTenantLmsConnection(db, {
        id: lmsConnectionId,
        tenantId,
        displayName: "Availability E2E LMS",
        providerKind: "sakai",
        apiBaseUrl: mockSakai.apiBaseUrl,
        accessToken: "SAKAIID=availability-e2e-session",
        ltiIssuer: mockLti.platform.issuer,
        ltiClientId: mockLti.platform.clientId,
        ltiDeploymentId: mockLti.platform.deploymentId,
      });
      await upsertLtiIssuerRegistration(db, {
        issuer: mockLti.platform.issuer,
        tenantId,
        authorizationEndpoint: mockLti.authorizationEndpoint,
        clientId: mockLti.platform.clientId,
        platformJwksEndpoint: mockLti.platformJwksEndpoint,
        tokenEndpoint: mockLti.tokenEndpoint,
      });
      const created = await createTestBadgeIssuanceRule(db, {
        tenantId,
        name: ruleName,
        description: "A disposable active rule used to verify placement availability.",
        badgeTemplateId,
        lmsProviderKind: "sakai",
        lmsConnectionId,
        ruleJson,
        changeSummary: "Create course-availability browser fixture",
        createdByUserId: admin.id,
      });
      await db
        .prepare(
          `
          UPDATE badge_issuance_rule_versions
          SET status = 'active', effective_starts_at = NULL, expires_at = NULL
          WHERE tenant_id = ? AND rule_id = ? AND id = ?
        `,
        )
        .bind(tenantId, created.rule.id, created.version.id)
        .run();
      await db
        .prepare(
          `
          UPDATE badge_issuance_rules
          SET active_version_id = ?
          WHERE tenant_id = ? AND id = ?
        `,
        )
        .bind(created.version.id, tenantId, created.rule.id)
        .run();

      return {
        tenantId,
        adminEmail,
        ruleName,
        departmentId: department.id,
        departmentName,
        courseTitle: mockSakai.courseTitle,
        secondCourseTitle: mockSakai.secondCourseTitle,
        rulesPath: `/tenants/${encodeURIComponent(tenantId)}/admin/rules`,
        initialRuleState: {
          activeVersionId: created.version.id,
          ruleJson,
          versionCount: 1,
        },
        ltiPlatform: mockLti.platform,
        readPlacementContexts: async () => {
          const placements = await db
            .prepare(
              `
              SELECT context_id AS contextId
              FROM lti_resource_link_placements
              WHERE tenant_id = ?
                AND rule_id = ?
                AND status = 'active'
              ORDER BY context_id ASC
            `,
            )
            .bind(tenantId, created.rule.id)
            .all<{ readonly contextId: string }>();

          return placements.results.map((placement) => placement.contextId);
        },
        readRuleState: async () => {
          const state = await db
            .prepare(
              `
              SELECT
                rule.active_version_id AS activeVersionId,
                version.rule_json AS ruleJson,
                (
                  SELECT COUNT(*)::INTEGER
                  FROM badge_issuance_rule_versions counted
                  WHERE counted.tenant_id = rule.tenant_id
                    AND counted.rule_id = rule.id
                ) AS versionCount
              FROM badge_issuance_rules rule
              JOIN badge_issuance_rule_versions version
                ON version.tenant_id = rule.tenant_id
               AND version.id = rule.active_version_id
              WHERE rule.tenant_id = ? AND rule.id = ?
            `,
            )
            .bind(tenantId, created.rule.id)
            .first<LiveRuleState>();

          if (state === null) {
            throw new Error("Course-availability browser fixture rule no longer exists");
          }

          return state;
        },
        dispose: async () => {
          await deleteFixture(db, { tenantId, userId: admin.id });
          await mockSakai.close();
          await mockLti.close();
        },
      };
    } catch (error) {
      if (tenantCreated) {
        if (adminUserId === null) {
          await db.prepare("DELETE FROM tenants WHERE id = ?").bind(tenantId).run();
        } else {
          await deleteFixture(db, { tenantId, userId: adminUserId });
        }
      }
      await mockSakai.close();
      await mockLti.close();
      throw error;
    }
  };
