import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PAGE_ASSET_CONTENT_DIR = join(dirname(fileURLToPath(import.meta.url)), "content");
export const PAGE_ASSET_SCRIPT_CONTENT_DIR = join(
  dirname(fileURLToPath(import.meta.url)),
  "content",
  "js",
);

export const readPageAssetContentFile = (sourcePath: string): string => {
  return readFileSync(join(PAGE_ASSET_CONTENT_DIR, sourcePath), "utf8");
};

export const readPageAssetBinaryContentFile = (sourcePath: string): Uint8Array => {
  return readFileSync(join(PAGE_ASSET_CONTENT_DIR, sourcePath));
};

export const readPageAssetScriptContentFile = (sourcePath: string): string => {
  return readFileSync(join(PAGE_ASSET_SCRIPT_CONTENT_DIR, sourcePath), "utf8");
};
