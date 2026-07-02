import type { AppContext } from "../app";

const optionalLtiLoginField = (
  value: string | null | undefined,
  field: string,
): Record<string, string> => {
  if (value === null || value === undefined) {
    return {};
  }

  return { [field]: value };
};

const ltiLoginFieldsFromEntries = (
  get: (field: string) => string | null | undefined,
): Record<string, string> => {
  return {
    iss: get("iss") ?? "",
    login_hint: get("login_hint") ?? "",
    target_link_uri: get("target_link_uri") ?? "",
    ...optionalLtiLoginField(get("client_id"), "client_id"),
    ...optionalLtiLoginField(get("lti_message_hint"), "lti_message_hint"),
    ...optionalLtiLoginField(get("lti_deployment_id"), "lti_deployment_id"),
    ...optionalLtiLoginField(get("lti_storage_target"), "lti_storage_target"),
  };
};

export const ltiLoginInputFromRequest = async (c: AppContext): Promise<Record<string, string>> => {
  if (c.req.method === "GET") {
    return ltiLoginFieldsFromEntries((field) => c.req.query(field));
  }

  const contentType = c.req.header("content-type") ?? "";

  if (!contentType.toLowerCase().includes("application/x-www-form-urlencoded")) {
    return {};
  }

  const rawBody = await c.req.text();
  const formData = new URLSearchParams(rawBody);

  return ltiLoginFieldsFromEntries((field) => formData.get(field));
};
