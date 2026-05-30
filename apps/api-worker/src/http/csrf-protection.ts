import { BETTER_AUTH_SESSION_COOKIE_NAME } from "../auth/better-auth-config";
import { LTI_LAUNCH_PATH, LTI_OIDC_LOGIN_PATH } from "../lti/constants";

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const CROSS_SITE_PROTOCOL_PATHS = new Set([LTI_OIDC_LOGIN_PATH, LTI_LAUNCH_PATH]);

const cookieHeaderContains = (cookieHeader: string | undefined, cookieName: string): boolean => {
  if (cookieHeader === undefined || cookieHeader.trim().length === 0) {
    return false;
  }

  return cookieHeader.split(";").some((cookie) => cookie.trim().startsWith(`${cookieName}=`));
};

const originFromHeaderValue = (value: string): string | null => {
  const trimmed = value.trim();

  if (trimmed.length === 0 || trimmed === "null") {
    return null;
  }

  try {
    return new URL(trimmed).origin;
  } catch {
    return null;
  }
};

interface ValidateCsrfRequestOriginInput {
  method: string;
  requestUrl: URL;
  cookieHeader?: string | undefined;
  originHeader?: string | undefined;
  refererHeader?: string | undefined;
}

export const validateCsrfRequestOrigin = (input: ValidateCsrfRequestOriginInput): boolean => {
  const method = input.method.toUpperCase();

  if (!STATE_CHANGING_METHODS.has(method)) {
    return true;
  }

  if (CROSS_SITE_PROTOCOL_PATHS.has(input.requestUrl.pathname)) {
    return true;
  }

  if (!cookieHeaderContains(input.cookieHeader, BETTER_AUTH_SESSION_COOKIE_NAME)) {
    return true;
  }

  const requestOrigin = input.requestUrl.origin;
  const originHeader = input.originHeader?.trim();

  if (originHeader !== undefined && originHeader.length > 0) {
    return originFromHeaderValue(originHeader) === requestOrigin;
  }

  const refererHeader = input.refererHeader?.trim();

  if (refererHeader !== undefined && refererHeader.length > 0) {
    return originFromHeaderValue(refererHeader) === requestOrigin;
  }

  return false;
};
