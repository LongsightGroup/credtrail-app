import { builtinModules } from "node:module";

const workspacePackageNames = new Set([
  "@credtrail/core-domain",
  "@credtrail/db",
  "@credtrail/ui-components",
  "@credtrail/validation",
]);

const nodeBuiltins = new Set([
  ...builtinModules,
  ...builtinModules.map((moduleName) => `node:${moduleName}`),
]);

function getPackageName(importId) {
  if (importId.startsWith("@")) {
    const [scope, name] = importId.split("/");
    return scope === undefined || name === undefined ? importId : `${scope}/${name}`;
  }

  const [name] = importId.split("/");
  return name ?? importId;
}

function isExternalImport(importId) {
  if (importId.startsWith(".") || importId.startsWith("/") || importId.includes("\0")) {
    return false;
  }

  if (nodeBuiltins.has(importId)) {
    return true;
  }

  return !workspacePackageNames.has(getPackageName(importId));
}

export default {
  input: {
    "node-server-runtime": "apps/api-worker/src/node-server-runtime.ts",
    "node-worker-runtime": "apps/api-worker/src/node-worker-runtime.ts",
  },
  external: isExternalImport,
  platform: "node",
  output: {
    dir: "apps/api-worker/dist/node-runtime",
    entryFileNames: "[name].js",
    format: "esm",
    sourcemap: true,
  },
  resolve: {
    conditionNames: ["node", "import", "default"],
    mainFields: ["module", "main"],
  },
  tsconfig: "./tsconfig.json",
};
