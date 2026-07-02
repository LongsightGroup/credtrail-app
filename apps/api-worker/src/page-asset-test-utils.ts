import { assembleScriptAsset } from "./ui/page-assets/assemble-script-asset";
import { assembleStyleAsset } from "./ui/page-assets/assemble-style-asset";
import { PAGE_ASSET_BUILD_SOURCES } from "./ui/page-assets/build-registry";
import {
  readPageAssetContentFile,
  readPageAssetScriptContentFile,
} from "./ui/page-assets/page-asset-content";
import type { PageAssetKey } from "./ui/page-assets";

export const readStyleSourceFile = readPageAssetContentFile;

export const readStyleAssetSource = (assetKey: PageAssetKey): string => {
  const source = PAGE_ASSET_BUILD_SOURCES[assetKey];

  if (source.kind !== "style") {
    throw new Error(`${assetKey} is not a style asset`);
  }

  return assembleStyleAsset(source.sources, readStyleSourceFile);
};

export const readScriptAssetSource = (assetKey: PageAssetKey): string => {
  const source = PAGE_ASSET_BUILD_SOURCES[assetKey];

  if (source.kind !== "script") {
    throw new Error(`${assetKey} is not a script asset`);
  }

  return assembleScriptAsset(source, readPageAssetScriptContentFile);
};
