const DEFAULT_MAILTRAP_API_BASE_URL = "https://sandbox.api.mailtrap.io/api/send";
const MAILTRAP_SANDBOX_HOST = "sandbox.api.mailtrap.io";

export const mailtrapConfigured = (input: {
  mailtrapApiToken?: string | undefined;
  mailtrapInboxId?: string | undefined;
  mailtrapApiBaseUrl?: string | undefined;
}): boolean => {
  if (input.mailtrapApiToken === undefined || input.mailtrapApiToken.trim().length === 0) {
    return false;
  }

  const baseUrl = input.mailtrapApiBaseUrl ?? DEFAULT_MAILTRAP_API_BASE_URL;
  const endpointUrl = new URL(baseUrl);

  if (
    endpointUrl.hostname === MAILTRAP_SANDBOX_HOST &&
    (input.mailtrapInboxId === undefined || input.mailtrapInboxId.trim().length === 0)
  ) {
    return false;
  }

  return true;
};

export const buildMailtrapSendEndpoint = (input: {
  mailtrapApiBaseUrl?: string | undefined;
  mailtrapInboxId?: string | undefined;
}): string => {
  const baseUrl = input.mailtrapApiBaseUrl ?? DEFAULT_MAILTRAP_API_BASE_URL;
  const endpointUrl = new URL(baseUrl);

  if (endpointUrl.hostname !== MAILTRAP_SANDBOX_HOST) {
    return baseUrl.replaceAll(/\/+$/g, "");
  }

  if (input.mailtrapInboxId === undefined || input.mailtrapInboxId.trim().length === 0) {
    throw new Error("Mailtrap sandbox inbox id is required");
  }

  return `${baseUrl.replaceAll(/\/+$/g, "")}/${encodeURIComponent(input.mailtrapInboxId)}`;
};
