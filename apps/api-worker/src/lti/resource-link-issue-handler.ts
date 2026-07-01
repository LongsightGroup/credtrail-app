import { findBadgeTemplateById, type SqlDatabase } from "@credtrail/db";
import type { AppBindings, AppContext } from "../app";
import type { DirectIssueBadgeResult } from "../badges/direct-issue";
import type { DirectIssueBadgeRequest } from "../badges/recipient-identifiers";
import { renderAppPage } from "../ui/render-page";
import { asNonEmptyString } from "../utils/value-parsers";
import { createCredTrailLtiTool } from "./credtrail-lti-tool";
import { verifyLtiIssuanceActionToken } from "./issuance-action-token";
import { ltiRosterIssuanceResultPage } from "./pages";
import {
  executeLtiRosterIssuance,
  LtiRosterIssuanceError,
  type ExecuteLtiRosterIssuanceResult,
} from "./roster-issuance";
import {
  ltiSessionMatchesIssuanceAction,
  selectedLearnerUserIdsFromForm,
} from "./roster-issuance-helpers";

/**
 * Dependencies required to handle instructor Resource Link badge issuance.
 */
export interface HandleLtiResourceLinkIssueInput {
  readonly c: AppContext;
  readonly resolveDatabase: (bindings: AppBindings) => SqlDatabase;
  readonly sha256Hex: (value: string) => Promise<string>;
  readonly issueBadgeForTenant: (
    c: AppContext,
    tenantId: string,
    request: DirectIssueBadgeRequest,
    issuedByUserId?: string,
    options?: {
      readonly recipientDisplayName?: string;
      readonly issuerName?: string;
      readonly issuerUrl?: string;
    },
  ) => Promise<DirectIssueBadgeResult>;
}

/**
 * Handles instructor-triggered Resource Link roster badge issuance.
 */
export const handleLtiResourceLinkIssue = async (
  input: HandleLtiResourceLinkIssueInput,
): Promise<Response> => {
  const { c, resolveDatabase, sha256Hex, issueBadgeForTenant } = input;
  const form = await c.req.formData();
  const actionToken = asNonEmptyString(form.get("issuance_action_token"));
  const selectedLearnerUserIds = selectedLearnerUserIdsFromForm(form);

  if (actionToken === null) {
    return c.json(
      {
        error: "issuance_action_token is required",
      },
      400,
    );
  }

  const issuanceAction = await verifyLtiIssuanceActionToken(c.env, actionToken);

  if (issuanceAction === null) {
    return c.json(
      {
        error: "LTI issuance action token is invalid or expired",
      },
      403,
    );
  }

  const db = resolveDatabase(c.env);
  const ltiTool = await createCredTrailLtiTool({
    db,
    env: c.env,
  });
  const ltiSession = await ltiTool.getSession(issuanceAction.ltiSessionId);

  if (ltiSession === undefined) {
    return c.json(
      {
        error: "LTI launch session was not found or is no longer active",
      },
      404,
    );
  }

  if (!ltiSessionMatchesIssuanceAction(ltiSession, issuanceAction)) {
    return c.json(
      {
        error: "LTI launch session does not match issuance action",
      },
      403,
    );
  }

  if (!ltiSession.isInstructor) {
    return c.json(
      {
        error: "LTI roster badge issuance requires an instructor launch",
      },
      403,
    );
  }

  const badgeTemplate = await findBadgeTemplateById(
    db,
    issuanceAction.tenantId,
    issuanceAction.badgeTemplateId,
  );

  if (badgeTemplate === null || badgeTemplate.isArchived) {
    return c.json(
      {
        error: "LTI resource-link badge template is not available for this tenant",
      },
      404,
    );
  }

  let issuanceResult: ExecuteLtiRosterIssuanceResult;

  try {
    issuanceResult = await executeLtiRosterIssuance({
      c,
      db,
      ltiTool,
      ltiSession,
      issuanceAction,
      selectedLearnerUserIds,
      sha256Hex,
      issueBadgeForTenant,
    });
  } catch (error: unknown) {
    if (error instanceof LtiRosterIssuanceError) {
      return c.json(
        {
          error: error.message,
        },
        error.status,
      );
    }

    throw error;
  }

  c.header("Cache-Control", "no-store");
  return renderAppPage(
    c,
    ltiRosterIssuanceResultPage({
      tenantId: issuanceResult.tenantId,
      badgeTemplateId: issuanceResult.badgeTemplateId,
      courseContextTitle: issuanceResult.courseContextTitle,
      selectedCount: issuanceResult.selectedCount,
      results: issuanceResult.results,
    }),
  );
};
