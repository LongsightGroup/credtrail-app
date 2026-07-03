import type { LtiLaunchSessionRecord } from "@credtrail/db";
import { parsePersistedLtiSession, type LTISession } from "@longsightgroup/lti-tool";

export const matchingPlacementSession = (input: {
  readonly sessions: readonly LtiLaunchSessionRecord[];
  readonly contextId: string | null;
  readonly resourceLinkId: string;
}): LTISession | null => {
  for (const sessionRecord of input.sessions) {
    const session = parsePersistedLtiSession(sessionRecord.dataJson);

    if (
      session !== undefined &&
      session.context.id === input.contextId &&
      session.resourceLink?.id === input.resourceLinkId
    ) {
      return session;
    }
  }

  return null;
};
