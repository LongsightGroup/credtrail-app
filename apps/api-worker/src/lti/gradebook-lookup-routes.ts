import { parseTenantLmsConnectionCourseSearchQuery } from "@credtrail/validation";
import type { Hono } from "hono";
import type { AppContext, AppEnv } from "../app";
import type { ResolveDatabase } from "../app/route-deps";
import { jsonError } from "../http/json-responses";
import {
  listGradebookItemsForCourse,
  listWorkflowStatesForAssignment,
  lmsLookupErrorMessage,
} from "../lms/gradebook-picker";
import { asNonEmptyString } from "../utils/value-parsers";
import { resolveLtiGradebookLookup } from "./gradebook-lookup";
import type { LtiIssuerRegistry } from "./lti-issuer-registry";

interface RegisterLtiGradebookLookupRoutesInput {
  app: Hono<AppEnv>;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: ResolveDatabase;
}

export const registerLtiGradebookLookupRoutes = (
  input: RegisterLtiGradebookLookupRoutesInput,
): void => {
  const { app, resolveLtiIssuerRegistry, resolveDatabase } = input;

  app.get("/v1/lti/deep-linking/sessions/:ltiSessionId/gradebook-items", async (c) => {
    const ltiSessionId = asNonEmptyString(c.req.param("ltiSessionId"));

    if (ltiSessionId === null) {
      return jsonError(c, 400, "ltiSessionId is required");
    }

    const resolved = await resolveLtiGradebookLookup({
      db: resolveDatabase(c.env),
      ltiSessionId,
      issuerRegistry: await resolveLtiIssuerRegistry(c),
      nowIso: new Date().toISOString(),
    });

    if ("error" in resolved) {
      return jsonError(c, resolved.status, resolved.error);
    }

    const query = parseTenantLmsConnectionCourseSearchQuery(c.req.query());

    try {
      const items = await listGradebookItemsForCourse({
        provider: resolved.provider,
        courseId: resolved.ltiSession.context.id,
        query: query.q,
      });

      return c.json({
        tenantId: resolved.tenantId,
        connectionId: resolved.connection.id,
        courseId: resolved.ltiSession.context.id,
        items,
      });
    } catch (error) {
      return c.json(
        {
          error: lmsLookupErrorMessage(
            resolved.connection,
            error,
            "Unable to list Sakai gradebook items",
          ),
        },
        502,
      );
    }
  });

  app.get(
    "/v1/lti/deep-linking/sessions/:ltiSessionId/gradebook-items/:assignmentId/workflow-states",
    async (c) => {
      const ltiSessionId = asNonEmptyString(c.req.param("ltiSessionId"));
      const assignmentId = asNonEmptyString(c.req.param("assignmentId"));

      if (ltiSessionId === null || assignmentId === null) {
        return jsonError(c, 400, "ltiSessionId and assignmentId are required");
      }

      const resolved = await resolveLtiGradebookLookup({
        db: resolveDatabase(c.env),
        ltiSessionId,
        issuerRegistry: await resolveLtiIssuerRegistry(c),
        nowIso: new Date().toISOString(),
      });

      if ("error" in resolved) {
        return jsonError(c, resolved.status, resolved.error);
      }

      try {
        const states = await listWorkflowStatesForAssignment({
          provider: resolved.provider,
          connection: resolved.connection,
          courseId: resolved.ltiSession.context.id,
          assignmentId,
        });

        return c.json({
          tenantId: resolved.tenantId,
          connectionId: resolved.connection.id,
          courseId: resolved.ltiSession.context.id,
          assignmentId,
          states,
        });
      } catch (error) {
        return c.json(
          {
            error: lmsLookupErrorMessage(
              resolved.connection,
              error,
              "Unable to list workflow state options",
            ),
          },
          502,
        );
      }
    },
  );
};
