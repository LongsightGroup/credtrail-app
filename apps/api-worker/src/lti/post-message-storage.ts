export const ltiPostMessageStorageRedirectInput = (input: {
  authorizationRedirectUrl: string;
  storageTarget: string | undefined;
}): {
  authorizationRedirectUrl: string;
  platformOrigin: string;
  storageTarget: string;
  state: string;
  nonce: string;
} | null => {
  if (input.storageTarget === undefined || input.storageTarget.trim().length === 0) {
    return null;
  }

  const redirectUrl = new URL(input.authorizationRedirectUrl);
  const state = redirectUrl.searchParams.get("state");
  const nonce = redirectUrl.searchParams.get("nonce");

  if (state === null || nonce === null) {
    return null;
  }

  return {
    authorizationRedirectUrl: redirectUrl.toString(),
    platformOrigin: redirectUrl.origin,
    storageTarget: input.storageTarget,
    state,
    nonce,
  };
};
