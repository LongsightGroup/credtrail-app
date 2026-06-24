import type { JsonObject } from "@credtrail/core-domain";
import type { AppContext } from "../app/types";
import { ob3ServiceDescriptionDocument as ob3ServiceDescriptionDocumentFromRequest } from "./service-description";

export const ob3ServiceDescriptionDocument = (c: AppContext): JsonObject => {
  return ob3ServiceDescriptionDocumentFromRequest({
    requestUrl: c.req.url,
    discoveryTitle: c.env.OB3_DISCOVERY_TITLE,
    termsOfServiceUrl: c.env.OB3_TERMS_OF_SERVICE_URL,
    privacyPolicyUrl: c.env.OB3_PRIVACY_POLICY_URL,
    imageUrl: c.env.OB3_IMAGE_URL,
    oauthRegistrationUrl: c.env.OB3_OAUTH_REGISTRATION_URL,
    oauthAuthorizationUrl: c.env.OB3_OAUTH_AUTHORIZATION_URL,
    oauthTokenUrl: c.env.OB3_OAUTH_TOKEN_URL,
    oauthRefreshUrl: c.env.OB3_OAUTH_REFRESH_URL,
  });
};
