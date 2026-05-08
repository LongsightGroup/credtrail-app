import type { Hono } from "hono";
import type { HtmlEscapedString } from "hono/utils/html";
import type { AppEnv } from "../../app";
import { AUTH_LOGIN_CSS } from "./content/auth-login-css";
import { AUTH_LOGIN_JS } from "./content/auth-login-js";
import { EXECUTIVE_DASHBOARD_CSS } from "./content/executive-dashboard-css";
import { FOUNDATION_CSS } from "./content/foundation-css";
import { INSTITUTION_ADMIN_CSS } from "./content/institution-admin-css";
import { INSTITUTION_ADMIN_JS } from "./content/institution-admin-js";
import { LEARNER_DASHBOARD_CSS } from "./content/learner-dashboard-css";
import { LEARNER_RECORD_CSS } from "./content/learner-record-css";
import { LTI_PAGES_CSS } from "./content/lti-pages-css";
import { LTI_POST_MESSAGE_STORAGE_JS } from "./content/lti-post-message-storage-js";
import { PUBLIC_BADGE_CSS } from "./content/public-badge-css";
import { PUBLIC_BADGE_JS } from "./content/public-badge-js";

type PageAssetKind = "style" | "script";

interface PageAssetSource {
  kind: PageAssetKind;
  stem: string;
  body: string;
  contentType: string;
}

const PAGE_ASSET_BASE_PATH = "/assets/ui";
const PAGE_ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable";

const PAGE_ASSET_SOURCES = {
  foundationCss: {
    kind: "style",
    stem: "foundation",
    body: FOUNDATION_CSS,
    contentType: "text/css; charset=utf-8",
  },
  authLoginCss: {
    kind: "style",
    stem: "auth-login",
    body: AUTH_LOGIN_CSS,
    contentType: "text/css; charset=utf-8",
  },
  authLoginJs: {
    kind: "script",
    stem: "auth-login",
    body: AUTH_LOGIN_JS,
    contentType: "text/javascript; charset=utf-8",
  },
  executiveDashboardCss: {
    kind: "style",
    stem: "executive-dashboard",
    body: EXECUTIVE_DASHBOARD_CSS,
    contentType: "text/css; charset=utf-8",
  },
  institutionAdminCss: {
    kind: "style",
    stem: "institution-admin",
    body: INSTITUTION_ADMIN_CSS,
    contentType: "text/css; charset=utf-8",
  },
  institutionAdminJs: {
    kind: "script",
    stem: "institution-admin",
    body: INSTITUTION_ADMIN_JS,
    contentType: "text/javascript; charset=utf-8",
  },
  learnerRecordCss: {
    kind: "style",
    stem: "learner-record",
    body: LEARNER_RECORD_CSS,
    contentType: "text/css; charset=utf-8",
  },
  learnerDashboardCss: {
    kind: "style",
    stem: "learner-dashboard",
    body: LEARNER_DASHBOARD_CSS,
    contentType: "text/css; charset=utf-8",
  },
  ltiPagesCss: {
    kind: "style",
    stem: "lti-pages",
    body: LTI_PAGES_CSS,
    contentType: "text/css; charset=utf-8",
  },
  ltiPostMessageStorageJs: {
    kind: "script",
    stem: "lti-post-message-storage",
    body: LTI_POST_MESSAGE_STORAGE_JS,
    contentType: "text/javascript; charset=utf-8",
  },
  publicBadgeCss: {
    kind: "style",
    stem: "public-badge",
    body: PUBLIC_BADGE_CSS,
    contentType: "text/css; charset=utf-8",
  },
  publicBadgeJs: {
    kind: "script",
    stem: "public-badge",
    body: PUBLIC_BADGE_JS,
    contentType: "text/javascript; charset=utf-8",
  },
} as const satisfies Record<string, PageAssetSource>;

interface BuiltPageAsset extends PageAssetSource {
  filename: string;
  path: string;
  cacheControl: string;
}

const hashContent = (value: string): string => {
  let hash = 0x811c9dc5;

  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }

  return hash.toString(16).padStart(8, "0");
};

const buildPageAssets = <T extends Record<string, PageAssetSource>>(
  sources: T,
): { [K in keyof T]: BuiltPageAsset & T[K] } => {
  const entries = Object.entries(sources).map(([key, source]) => {
    const extension = source.kind === "style" ? "css" : "js";
    const filename = `${source.stem}.${hashContent(source.body)}.${extension}`;
    const built: BuiltPageAsset = {
      ...source,
      filename,
      path: `${PAGE_ASSET_BASE_PATH}/${filename}`,
      cacheControl: PAGE_ASSET_CACHE_CONTROL,
    };

    return [key, built] as const;
  });

  return Object.fromEntries(entries) as { [K in keyof T]: BuiltPageAsset & T[K] };
};

const PAGE_ASSETS = buildPageAssets(PAGE_ASSET_SOURCES);
const PAGE_ASSETS_BY_FILENAME = new Map<string, BuiltPageAsset>(
  Object.values(PAGE_ASSETS).map((asset) => [asset.filename, asset]),
);

export type PageAssetKey = keyof typeof PAGE_ASSETS;

type PageAssetKeysByKind<Kind extends PageAssetKind> = {
  [Key in PageAssetKey]: (typeof PAGE_ASSETS)[Key]["kind"] extends Kind ? Key : never;
}[PageAssetKey];

export type PageStylesheetAssetKey = PageAssetKeysByKind<"style">;
export type PageScriptAssetKey = PageAssetKeysByKind<"script">;

export const pageAssetPath = (key: PageAssetKey): string => {
  return PAGE_ASSETS[key].path;
};

export const PageAssets = (input: { keys: readonly PageAssetKey[] }): HonoElement => {
  return (
    <>
      {input.keys.map((key) => {
        const asset = PAGE_ASSETS[key];

        if (asset.kind === "style") {
          return <link rel="stylesheet" href={asset.path} />;
        }

        return <script defer src={asset.path}></script>;
      })}
    </>
  );
};

export const registerPageAssetRoutes = (input: { app: Hono<AppEnv> }): void => {
  const { app } = input;

  app.get(`${PAGE_ASSET_BASE_PATH}/:assetFilename`, (c) => {
    const assetFilename = c.req.param("assetFilename");
    const asset = PAGE_ASSETS_BY_FILENAME.get(assetFilename);

    if (asset === undefined) {
      return c.notFound();
    }

    c.header("Cache-Control", asset.cacheControl);
    c.header("Content-Type", asset.contentType);
    c.header("X-Content-Type-Options", "nosniff");

    return c.body(asset.body);
  });
};
type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
