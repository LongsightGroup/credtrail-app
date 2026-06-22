import { appPage, type AppPage } from "../ui/render-page";
import { buildSeoHeadContent } from "./public-badge-renderer-helpers";

export const createPublicBadgeNotFoundPage = (): ((requestUrl: string) => AppPage) => {
  return (requestUrl: string): AppPage => {
    const canonicalUrl = new URL(requestUrl).toString();

    return appPage({
      title: "Badge not found",
      head: buildSeoHeadContent({
        title: "Badge not found | CredTrail",
        description: "The shared badge URL is invalid or the credential does not exist.",
        canonicalUrl,
        ogType: "website",
        robots: "noindex, nofollow",
      }),
      assets: ["publicBadgeCss"],
      body: (
        <section class="public-badge-not-found">
          <article class="public-badge-not-found__card">
            <p class="public-badge-not-found__eyebrow">Public Badge Lookup</p>
            <h1 class="public-badge-not-found__title">Badge not found</h1>
            <p class="public-badge-not-found__copy">
              The shared badge URL is invalid or the credential does not exist.
            </p>
          </article>
        </section>
      ),
    });
  };
};
