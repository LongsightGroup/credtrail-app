import {
  findLtiLaunchSessionById,
  listTenantLmsConnections,
  type SqlDatabase,
  type TenantLmsConnectionRecord,
} from "@credtrail/db";
import { parsePersistedLtiSession, resolveLtiServiceCapabilities } from "@lti-tool/core";
import { createGradebookProviderForConnection } from "../lms/gradebook-provider-resolution";
import type { GradebookProvider } from "../lms/gradebook-types";
import { findLtiIssuerRegistryEntry } from "./deep-linking-helpers";
import { matchingSakaiLmsConnection } from "./course-badge-setup";
import type { LtiIssuerRegistry } from "./lti-helpers";

export interface LtiGradebookLookupSession {
  context: {
    id: string;
  };
  platform: {
    issuer: string;
    clientId: string;
    deploymentId: string;
  };
  hasDeepLinkingService: boolean;
  isInstructor?: boolean;
}

export interface ResolvedLtiGradebookLookup {
  tenantId: string;
  ltiSession: LtiGradebookLookupSession;
  connection: TenantLmsConnectionRecord;
  provider: GradebookProvider;
}

export type LtiGradebookLookupFailure = {
  status: 400 | 403 | 404 | 409;
  error: string;
};

export const parsePersistedLtiSessionDataJson = (
  dataJson: string,
): LtiGradebookLookupSession | null => {
  const session = parsePersistedLtiSession(dataJson);

  if (session === undefined) {
    return null;
  }

  const capabilities = resolveLtiServiceCapabilities(session);

  return {
    context: {
      id: session.context.id,
    },
    platform: {
      issuer: session.platform.issuer,
      clientId: session.platform.clientId,
      deploymentId: session.platform.deploymentId,
    },
    hasDeepLinkingService: capabilities.deepLinking.available,
    isInstructor: session.isInstructor,
  };
};

export const resolveLtiGradebookLookup = async (input: {
  db: SqlDatabase;
  ltiSessionId: string;
  issuerRegistry: LtiIssuerRegistry;
  nowIso: string;
}): Promise<ResolvedLtiGradebookLookup | LtiGradebookLookupFailure> => {
  const persistedSession = await findLtiLaunchSessionById(input.db, input.ltiSessionId);

  if (persistedSession === null) {
    return {
      status: 404,
      error: "LTI Deep Linking session was not found or is no longer active",
    };
  }

  const ltiSession = parsePersistedLtiSessionDataJson(persistedSession.dataJson);

  if (ltiSession === null) {
    return { status: 400, error: "LTI launch session data is invalid" };
  }

  if (!ltiSession.hasDeepLinkingService) {
    return {
      status: 404,
      error: "LTI Deep Linking session was not found or is no longer active",
    };
  }

  if (ltiSession.isInstructor !== true) {
    return { status: 403, error: "LTI instructor role is required for gradebook lookup" };
  }

  if (persistedSession.userId === null) {
    return {
      status: 400,
      error: "LTI launch session is missing linked user context",
    };
  }

  const tenantId = persistedSession.tenantId;

  if (tenantId === null) {
    return {
      status: 400,
      error: "LTI launch session is missing tenant context",
    };
  }

  if (ltiSession.context.id.trim().length === 0) {
    return {
      status: 400,
      error: "LTI course context is required for gradebook lookup",
    };
  }

  const issuerMatch = findLtiIssuerRegistryEntry(
    input.issuerRegistry,
    ltiSession.platform.issuer,
    ltiSession.platform.clientId,
  );

  if (issuerMatch === null || issuerMatch.entry.tenantId !== tenantId) {
    return {
      status: 404,
      error: "LTI issuer registration was not found for this Deep Linking session",
    };
  }

  const connections = await listTenantLmsConnections(input.db, tenantId);
  const connection = matchingSakaiLmsConnection(connections, {
    issuer: ltiSession.platform.issuer,
    clientId: ltiSession.platform.clientId,
    deploymentId: ltiSession.platform.deploymentId,
  });

  if (connection === null) {
    return {
      status: 409,
      error:
        "CredTrail could not find a Sakai gradebook connection linked to this LTI launch. Add a Sakai LMS connection with matching issuer, client, and deployment before using gradebook evidence.",
    };
  }

  try {
    return {
      tenantId,
      ltiSession,
      connection,
      provider: await createGradebookProviderForConnection({
        db: input.db,
        connection,
        nowIso: input.nowIso,
      }),
    };
  } catch (error) {
    return {
      status: 409,
      error:
        error instanceof Error
          ? error.message
          : "Sakai gradebook access is unavailable. Save Sakai username and password credentials for an account that can view the target site and gradebook.",
    };
  }
};
