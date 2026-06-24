import { parseTenantLmsConnectionCourseSearchQuery } from "@credtrail/validation";
import type { SqlDatabase } from "@credtrail/db";
import type { Hono } from "hono";
import type { AppBindings, AppContext, AppEnv } from "../app";
import {
  listGradebookItemsForCourse,
  listWorkflowStatesForAssignment,
  lmsLookupErrorMessage,
} from "../lms/gradebook-picker";
import { asNonEmptyString } from "../utils/value-parsers";
import type { LtiIssuerRegistry } from "./lti-helpers";
import { resolveLtiGradebookLookup } from "./gradebook-lookup";

interface RegisterLtiGradebookLookupRoutesInput {
  app: Hono<AppEnv>;
  resolveLtiIssuerRegistry: (context: AppContext) => Promise<LtiIssuerRegistry>;
  resolveDatabase: (bindings: AppBindings) => SqlDatabase;
}

export const registerLtiGradebookLookupRoutes = (
  input: RegisterLtiGradebookLookupRoutesInput,
): void => {
  const { app, resolveLtiIssuerRegistry, resolveDatabase } = input;

  app.get("/v1/lti/deep-linking/sessions/:ltiSessionId/gradebook-items", async (c) => {
    const ltiSessionId = asNonEmptyString(c.req.param("ltiSessionId"));

    if (ltiSessionId === null) {
      return c.json({ error: "ltiSessionId is required" }, 400);
    }

    const resolved = await resolveLtiGradebookLookup({
      db: resolveDatabase(c.env),
      ltiSessionId,
      issuerRegistry: await resolveLtiIssuerRegistry(c),
      nowIso: new Date().toISOString(),
    });

    if ("error" in resolved) {
      return c.json({ error: resolved.error }, resolved.status);
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
        return c.json({ error: "ltiSessionId and assignmentId are required" }, 400);
      }

      const resolved = await resolveLtiGradebookLookup({
        db: resolveDatabase(c.env),
        ltiSessionId,
        issuerRegistry: await resolveLtiIssuerRegistry(c),
        nowIso: new Date().toISOString(),
      });

      if ("error" in resolved) {
        return c.json({ error: resolved.error }, resolved.status);
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
