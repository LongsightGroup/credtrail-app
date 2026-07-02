import { readFileSync } from "node:fs";
import { PAGE_ASSET_BUILD_SOURCES } from "./ui/page-assets/build-registry";
import type { PageAssetKey } from "./ui/page-assets";

export const readStyleAssetSource = (assetKey: PageAssetKey): string => {
  const source = PAGE_ASSET_BUILD_SOURCES[assetKey];

  if (source.kind !== "style") {
    throw new Error(`${assetKey} is not a style asset`);
  }

  return source.sourcePaths
    .map((sourcePath) => {
      return readFileSync(
        new URL(`./ui/page-assets/content/${sourcePath}`, import.meta.url),
        "utf8",
      );
    })
    .join("\n");
};
