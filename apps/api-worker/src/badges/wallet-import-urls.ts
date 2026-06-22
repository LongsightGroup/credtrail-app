export interface PublicBadgeWalletImportUrls {
  walletOfferPath: string;
  walletOfferUrl: string;
  walletDeepLinkUrl: string;
  dccExchangePath: string;
  dccExchangeUrl: string;
  dccWalletDeepLinkUrl: string;
  walletQrCodePath: string;
}

export const buildPublicBadgeWalletImportUrls = (
  requestUrl: string,
  badgeIdentifier: string,
): PublicBadgeWalletImportUrls => {
  const requestOrigin = new URL(requestUrl).origin;
  const publicBadgePath = `/badges/${encodeURIComponent(badgeIdentifier)}`;
  const walletOfferPath = `/credentials/v1/offers/${encodeURIComponent(badgeIdentifier)}`;
  const walletOfferUrl = new URL(walletOfferPath, requestUrl).toString();
  const walletDeepLinkUrl = new URL("openid-credential-offer://");
  walletDeepLinkUrl.searchParams.set("credential_offer_uri", walletOfferUrl);
  const dccExchangePath = `/credentials/v1/dcc/exchanges/${encodeURIComponent(badgeIdentifier)}`;
  const dccExchangeUrl = new URL(dccExchangePath, requestUrl).toString();
  const dccInvitationRequest = {
    credentialRequestOrigin: requestOrigin,
    protocols: {
      vcapi: dccExchangeUrl,
    },
  };
  const dccWalletDeepLinkUrl = new URL("https://lcw.app/request");
  dccWalletDeepLinkUrl.searchParams.set("request", JSON.stringify(dccInvitationRequest));

  return {
    walletOfferPath,
    walletOfferUrl,
    walletDeepLinkUrl: walletDeepLinkUrl.toString(),
    dccExchangePath,
    dccExchangeUrl,
    dccWalletDeepLinkUrl: dccWalletDeepLinkUrl.toString(),
    walletQrCodePath: `${publicBadgePath}/wallet-qr.svg`,
  };
};
