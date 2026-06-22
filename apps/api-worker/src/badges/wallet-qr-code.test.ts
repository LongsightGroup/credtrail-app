import { describe, expect, it } from "vitest";

import { renderWalletQrCodeSvg, walletQrCodePayloadFromDeepLink } from "./wallet-qr-code";

describe("wallet QR code", () => {
  it("renders an SVG image for wallet import deep links", () => {
    const payload = walletQrCodePayloadFromDeepLink(
      "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fcredtrail.test%2Fcredentials%2Fv1%2Foffers%2Fabc",
    );
    const svg = renderWalletQrCodeSvg(payload);

    expect(svg.startsWith("<?xml") || svg.includes("<svg")).toBe(true);
    expect(svg).toContain("<svg");
    expect(svg).toContain("</svg>");
  });
});
