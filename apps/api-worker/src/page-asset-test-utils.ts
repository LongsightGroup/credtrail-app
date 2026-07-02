import { readFileSync } from "node:fs";
import {
  PAGE_ASSET_BUILD_SOURCES,
  type StylePageAssetSource,
} from "./ui/page-assets/build-registry";
import type { PageAssetKey } from "./ui/page-assets";

const readStyleSourcePath = (sourcePath: string): string => {
  return readFileSync(new URL(`./ui/page-assets/content/${sourcePath}`, import.meta.url), "utf8");
};

const readStyleSource = (source: StylePageAssetSource): string => {
  if (typeof source === "string") {
    return readStyleSourcePath(source);
  }

  return `@media ${source.media} {\n${source.sourcePaths.map(readStyleSourcePath).join("\n")}\n}`;
};

export const readStyleAssetSource = (assetKey: PageAssetKey): string => {
  const source = PAGE_ASSET_BUILD_SOURCES[assetKey];

  if (source.kind !== "style") {
    throw new Error(`${assetKey} is not a style asset`);
  }

  return source.sources.map(readStyleSource).join("\n");
};
