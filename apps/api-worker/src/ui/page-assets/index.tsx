import type { HtmlEscapedString } from "hono/utils/html";
import { PAGE_ASSET_MANIFEST } from "./generated/page-assets-manifest";

type PageAssetKind = "style" | "script";

interface PageAsset {
  kind: PageAssetKind;
  path: string;
}

const PAGE_ASSETS = PAGE_ASSET_MANIFEST satisfies Record<string, PageAsset>;

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

type HonoElement = HtmlEscapedString | Promise<HtmlEscapedString>;
