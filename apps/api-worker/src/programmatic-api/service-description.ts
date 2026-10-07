import type { JsonObject } from "@credtrail/core-domain";
import {
  jsonObjectSchema,
  type ProgrammaticApiScope,
  programmaticIssueBadgeRequestSchema,
  programmaticRevokeBadgeRequestSchema,
  programmaticAcceptedSchema,
  programmaticOperationSchema,
  programmaticErrorSchema,
  programmaticAssertionPageSchema,
  programmaticAssertionSchema,
  programmaticTemplatePageSchema,
  programmaticTemplateSchema,
  programmaticTenantQuerySchema,
  programmaticAssertionQuerySchema,
  programmaticTemplateQuerySchema,
} from "@credtrail/validation";
import { z } from "zod";
import { canonicalAppOrigin } from "../http/canonical-app-url";

const jsonSchema = (schema: z.ZodType, io: "input" | "output" = "output") =>
  jsonObjectSchema.parse(z.toJSONSchema(schema, { io }));
const ref = (name: string): JsonObject => ({ $ref: `#/components/schemas/${name}` });
const response = (description: string, name: string): JsonObject => ({
  description,
  content: { "application/json": { schema: ref(name) } },
});
const errors = {
  "400": response(
    "Malformed JSON, invalid parameters, or unknown request fields (invalid_request).",
    "Error",
  ),
  "401": response(
    "Missing, expired, revoked, or invalid integration key (api_key_required, invalid_api_key).",
    "Error",
  ),
  "403": response(
    "Wrong institution, missing permission, invalid key scopes, or missing write owner.",
    "Error",
  ),
  "404": response(
    "Resource not found in this institution (operation_not_found, template_not_found, assertion_not_found).",
    "Error",
  ),
};
const queryParameters = (schema: z.ZodType): JsonObject[] => {
  const object = z
    .object({
      properties: z.record(z.string(), z.unknown()),
      required: z.array(z.string()).optional(),
    })
    .parse(jsonSchema(schema, "input"));
  return Object.entries(object.properties).map(([name, value]) => ({
    name,
    in: "query",
    required: object.required?.includes(name) ?? false,
    // JSON Schema is emitted by Zod; this parser narrows it into the public JSON contract.
    schema: z.record(z.string(), z.json()).parse(value),
  }));
};
const pathParameter = (name: string): JsonObject => ({
  name,
  in: "path",
  required: true,
  schema: { type: "string", minLength: 1, maxLength: 256 },
});
const read = (
  operationId: string,
  summary: string,
  scope: ProgrammaticApiScope,
  parameters: JsonObject[],
  schema: string,
): JsonObject => ({
  operationId,
  summary,
  "x-required-scope": scope,
  parameters,
  responses: { "200": response("Successful institution-scoped read.", schema), ...errors },
});
const write = (operationId: string, scope: ProgrammaticApiScope, schema: string): JsonObject => ({
  operationId,
  summary: operationId === "issueBadge" ? "Queue badge issuance" : "Queue badge revocation",
  "x-required-scope": scope,
  description:
    "idempotencyKey is required. Matching replays return the original operationId and assertionId. Reuse with different content returns 409. Poll statusUrl with operations.read; acceptance is not completion.",
  requestBody: { required: true, content: { "application/json": { schema: ref(schema) } } },
  responses: {
    "202": {
      ...response(
        "Persisted or replayed command. Follow statusUrl using your integration key.",
        "Accepted",
      ),
      headers: {
        Location: {
          description: "Canonical status URL.",
          schema: { type: "string", format: "uri" },
        },
      },
    },
    ...errors,
    "409": response(
      "Idempotency conflict, archived template, or missing usable artwork (idempotency_conflict, template_archived, artwork_required).",
      "Error",
    ),
    ...(operationId === "issueBadge"
      ? { "422": response("Expiry must be later than the issue date (invalid_expiry).", "Error") }
      : {}),
    "503": response("Object storage is temporarily unavailable (storage_unavailable).", "Error"),
  },
});

// Schema generation is static. Only the configured public server varies between requests.
const description: JsonObject = {
  openapi: "3.1.0",
  info: {
    title: "CredTrail Institution Integration API",
    version: "1.0.0",
    description:
      "Issue, revoke, track completion, discover templates, and reconcile institution credentials. Supply x-api-key. List pages sort by immutable ID ascending; pass nextCursor unchanged and retain the same filters. Dates are inclusive UTC calendar dates. Only email identities use case-insensitive matching. Authenticated responses are never cached.",
  },
  security: [{ IntegrationKey: [] }],
  paths: {
    "/v1/programmatic/issue": { post: write("issueBadge", "queue.issue", "IssueRequest") },
    "/v1/programmatic/revoke": { post: write("revokeBadge", "queue.revoke", "RevokeRequest") },
    "/v1/programmatic/operations/{operationId}": {
      get: {
        ...read(
          "getOperation",
          "Check issuance or revocation completion",
          "operations.read",
          [...queryParameters(programmaticTenantQuerySchema), pathParameter("operationId")],
          "Operation",
        ),
        description:
          "Pending includes nextAttemptAt. Processing is in progress. Completed includes public links (null if the assertion is no longer available). Failed is terminal and contains a safe failure message. Completion does not guarantee email delivery. Pending and processing include Retry-After: 5. A matching command replay does not restart failed work.",
      },
    },
    "/v1/programmatic/templates": {
      get: read(
        "listTemplates",
        "List badge templates",
        "templates.read",
        queryParameters(programmaticTemplateQuerySchema),
        "TemplatePage",
      ),
    },
    "/v1/programmatic/templates/{badgeTemplateId}": {
      get: read(
        "getTemplate",
        "Get a badge template",
        "templates.read",
        [...queryParameters(programmaticTenantQuerySchema), pathParameter("badgeTemplateId")],
        "Template",
      ),
    },
    "/v1/programmatic/assertions": {
      get: read(
        "listAssertions",
        "Reconcile issued badges",
        "assertions.read",
        queryParameters(programmaticAssertionQuerySchema),
        "AssertionPage",
      ),
    },
    "/v1/programmatic/assertions/{assertionId}": {
      get: read(
        "getAssertion",
        "Get an issued badge",
        "assertions.read",
        [...queryParameters(programmaticTenantQuerySchema), pathParameter("assertionId")],
        "Assertion",
      ),
    },
  },
  components: {
    securitySchemes: { IntegrationKey: { type: "apiKey", in: "header", name: "x-api-key" } },
    schemas: {
      IssueRequest: jsonSchema(programmaticIssueBadgeRequestSchema, "input"),
      RevokeRequest: jsonSchema(programmaticRevokeBadgeRequestSchema, "input"),
      Accepted: jsonSchema(programmaticAcceptedSchema),
      Operation: jsonSchema(programmaticOperationSchema),
      Error: jsonSchema(programmaticErrorSchema),
      Template: jsonSchema(programmaticTemplateSchema),
      TemplatePage: jsonSchema(programmaticTemplatePageSchema),
      Assertion: jsonSchema(programmaticAssertionSchema),
      AssertionPage: jsonSchema(programmaticAssertionPageSchema),
    },
  },
};

/** OpenAPI 3.1 generated once from runtime schemas, with the configured public server. */
export const programmaticApiDescription = (publicOrigin: string): JsonObject => ({
  ...description,
  servers: [{ url: canonicalAppOrigin(publicOrigin) }],
});
