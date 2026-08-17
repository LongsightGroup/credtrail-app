import { listBadgeTemplates, type SqlDatabase } from "@credtrail/db";
import { LTI_CLAIM_DEPLOYMENT_ID } from "@longsightgroup/lti-tool";
import type { AppContext } from "../app/types";
import { canonicalAppRequestUrl } from "../http/canonical-app-url";
import { renderAppPage } from "../ui/render-page";
import { listLtiInstructorPlaceableBadgeTemplates } from "./course-badge-governance";
import { ltiDeepLinkSelectionInput } from "./deep-linking-helpers";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import type { DeepLinkingLaunchMessage } from "./launch-product-types";
import type { ResolvedLtiLaunch } from "./launch-verification";
import { ltiDeepLinkSelectionPage } from "./pages";

/**
 * Renders CredTrail's product UI for a verified LTI Deep Linking launch.
 */
export const renderLtiDeepLinkingLaunchResponse = async (input: {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  launchMessage: DeepLinkingLaunchMessage;
  resolvedLaunch: ResolvedLtiLaunch;
  linkedAccount: LinkedLtiLaunchAccount;
}): Promise<Response> => {
  const badgeTemplates = await listBadgeTemplates(input.db, {
    tenantId: input.tenantId,
    includeArchived: false,
  });
  const placeableBadgeTemplates = await listLtiInstructorPlaceableBadgeTemplates(input.db, {
    tenantId: input.tenantId,
    userId: input.linkedAccount.userId,
    badgeTemplates,
  });

  return renderAppPage(
    input.c,
    ltiDeepLinkSelectionPage(
      ltiDeepLinkSelectionInput({
        requestUrl: canonicalAppRequestUrl(input.c.env.PUBLIC_APP_ORIGIN, input.c.req.url),
        tenantId: input.tenantId,
        userId: input.linkedAccount.userId,
        membershipRole: input.linkedAccount.membershipRole,
        issuer: input.launchClaims.iss,
        deploymentId: input.launchClaims[LTI_CLAIM_DEPLOYMENT_ID],
        deepLinkReturnUrl: input.launchMessage.deepLinkingSettings.deepLinkReturnUrl,
        targetLinkUri: input.launchMessage.resolvedTargetLinkUri,
        ltiLaunchSession: input.resolvedLaunch.ltiLaunchSession,
        badgeTemplates: placeableBadgeTemplates,
      }),
    ),
  );
};
