import { renderQrCodeSvg } from "./qr-code";

export const walletQrCodePayloadFromDeepLink = (walletDeepLinkUrl: string): string => {
  return walletDeepLinkUrl;
};

export const renderWalletQrCodeSvg = (payload: string): string => {
  return renderQrCodeSvg(payload);
};
