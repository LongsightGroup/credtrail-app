import { describe, expect, it } from "vitest";

import { buildPublicBadgeWalletImportUrls } from "./wallet-import-urls";

describe("buildPublicBadgeWalletImportUrls", () => {
  it("builds wallet import URLs for a public badge", () => {
    const urls = buildPublicBadgeWalletImportUrls(
      "https://credtrail.test/badges/badge-123",
      "badge-123",
    );

    expect(urls.walletOfferUrl).toBe("https://credtrail.test/credentials/v1/offers/badge-123");
    expect(urls.walletDeepLinkUrl).toContain("openid-credential-offer://");
    expect(urls.walletDeepLinkUrl).toContain(
      "credential_offer_uri=https%3A%2F%2Fcredtrail.test%2Fcredentials%2Fv1%2Foffers%2Fbadge-123",
    );
    expect(urls.dccExchangeUrl).toBe(
      "https://credtrail.test/credentials/v1/dcc/exchanges/badge-123",
    );
    expect(urls.dccWalletDeepLinkUrl).toContain("https://lcw.app/request");
    expect(urls.walletQrCodePath).toBe("/badges/badge-123/wallet-qr.svg");
  });
});
