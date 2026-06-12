/// <reference types="node" />

import { cloudflare } from "@cloudflare/vite-plugin";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";

const configPath = process.env.CLOUDFLARE_VITE_WRANGLER_CONFIG_PATH ?? "wrangler.local.jsonc";

const buildPageAssets = (): void => {
  const result = spawnSync("pnpm", ["exec", "tsx", "scripts/build-page-assets.mjs"], {
    stdio: "inherit",
    env: process.env,
  });

  if (result.status !== 0) {
    throw new Error(`build-page-assets failed with exit code ${result.status ?? "unknown"}`);
  }
};

const pageAssetBuilder = (): Plugin => {
  const watchedPaths = [
    resolve("apps/api-worker/src/ui/page-assets/content"),
    resolve("apps/api-worker/src/ui/page-assets/build-registry.ts"),
    resolve("scripts/build-page-assets.mjs"),
  ];

  const shouldRebuild = (filePath: string): boolean => {
    return watchedPaths.some((watchedPath) => filePath.startsWith(watchedPath));
  };

  return {
    name: "credtrail-page-assets",
    buildStart: buildPageAssets,
    configureServer(server) {
      for (const watchedPath of watchedPaths) {
        server.watcher.add(watchedPath);
      }

      server.watcher.on("all", (_eventName, filePath) => {
        if (!shouldRebuild(filePath)) {
          return;
        }

        buildPageAssets();
        server.ws.send({ type: "full-reload" });
      });
    },
  };
};

export default defineConfig({
  publicDir: "apps/api-worker/public",
  plugins: [pageAssetBuilder(), cloudflare({ configPath })],
});
