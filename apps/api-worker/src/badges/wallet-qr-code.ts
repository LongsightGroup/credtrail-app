import qrcode from "qrcode-generator";

const QR_ERROR_CORRECTION_LEVEL = "M";

export const walletQrCodePayloadFromDeepLink = (walletDeepLinkUrl: string): string => {
  return walletDeepLinkUrl;
};

export const renderWalletQrCodeSvg = (payload: string): string => {
  const qr = qrcode(0, QR_ERROR_CORRECTION_LEVEL);
  qr.addData(payload);
  qr.make();

  return qr.createSvgTag({
    cellSize: 4,
    margin: 0,
    scalable: true,
  });
};
