import { createHash } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FONT_ASSET_SOURCES,
  PAGE_ASSET_BUILD_SOURCES,
} from "../apps/api-worker/src/ui/page-assets/build-registry.ts";

const repoRoot = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const publicRoot = join(repoRoot, "apps/api-worker/public");
const assetRoot = join(publicRoot, "assets/ui");
const fontAssetRoot = join(assetRoot, "fonts");
const cssSourceRoot = join(repoRoot, "apps/api-worker/src/ui/page-assets/content");
const manifestPath = join(
  repoRoot,
  "apps/api-worker/src/ui/page-assets/generated/page-assets-manifest.ts",
);

const hashBody = (body) => {
  return createHash("sha256").update(body).digest("hex").slice(0, 10);
};
const fontAssetBasePath = "/assets/ui/fonts";

await rm(assetRoot, { force: true, recursive: true });
await mkdir(fontAssetRoot, { recursive: true });
await mkdir(dirname(manifestPath), { recursive: true });

const fontPathByOriginalPath = new Map();
const fontEntries = Object.values(FONT_ASSET_SOURCES).map((source) => {
  const body = Buffer.from(source.bodyBase64, "base64");
  const extension = source.filename.split(".").at(-1) ?? "woff2";
  const stem = source.filename.slice(0, -(extension.length + 1));
  const filename = `${stem}.${hashBody(body)}.${extension}`;
  const originalPath = `${fontAssetBasePath}/${source.filename}`;
  const path = `${fontAssetBasePath}/${filename}`;

  fontPathByOriginalPath.set(originalPath, path);

  return { body, filename };
});

for (const font of fontEntries) {
  await writeFile(join(fontAssetRoot, font.filename), font.body);
}

const replaceFontPaths = (body) => {
  let nextBody = body;

  for (const [originalPath, hashedPath] of fontPathByOriginalPath) {
    nextBody = nextBody.split(originalPath).join(hashedPath);
  }

  return nextBody;
};

const readStyleAssetBody = async (sourcePaths) => {
  const sourceBodies = [];

  for (const sourcePath of sourcePaths) {
    sourceBodies.push(await readFile(join(cssSourceRoot, sourcePath), "utf8"));
  }

  return replaceFontPaths(sourceBodies.join("\n"));
};

const pageManifestEntries = [];

for (const [key, source] of Object.entries(PAGE_ASSET_BUILD_SOURCES)) {
  const extension = source.kind === "style" ? "css" : "js";
  const body = source.kind === "style" ? await readStyleAssetBody(source.sourcePaths) : source.body;
  const filename = `${source.stem}.${hashBody(body)}.${extension}`;
  const path = `/assets/ui/${filename}`;

  pageManifestEntries.push({ key, kind: source.kind, path });
  await writeFile(join(assetRoot, filename), body);
}

const manifestEntriesBody = pageManifestEntries
  .map((entry) => {
    return `  ${entry.key}: {\n    kind: ${JSON.stringify(entry.kind)},\n    path: ${JSON.stringify(
      entry.path,
    )},\n  },`;
  })
  .join("\n");
const manifestBody = `export const PAGE_ASSET_MANIFEST = {\n${manifestEntriesBody}\n} as const;\n`;
const headersBody = `/assets/ui/*\n  Cache-Control: public, max-age=31536000, immutable\n  X-Content-Type-Options: nosniff\n`;

await writeFile(manifestPath, manifestBody);
await writeFile(join(publicRoot, "_headers"), headersBody);

console.log(
  `Built ${Object.keys(PAGE_ASSET_BUILD_SOURCES).length} page assets and ${
    fontEntries.length
  } font assets.`,
);
