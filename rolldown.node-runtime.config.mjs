import { builtinModules } from "node:module";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const workspaceRoot = dirname(fileURLToPath(import.meta.url));
const workspacePackageNames = readWorkspacePackageNames(workspaceRoot);
const isProductionBuild = process.env.NODE_ENV === "production";

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

function readWorkspacePackagePatterns(root) {
  const workspaceYaml = readFileSync(join(root, "pnpm-workspace.yaml"), "utf8");
  const patterns = [];
  let inPackagesList = false;

  for (const line of workspaceYaml.split(/\r?\n/)) {
    if (line.trim() === "packages:") {
      inPackagesList = true;
      continue;
    }

    if (!inPackagesList) {
      continue;
    }

    const packagePatternMatch = line.match(/^\s*-\s+["']?([^"']+)["']?\s*$/u);
    if (packagePatternMatch) {
      patterns.push(packagePatternMatch[1]);
      continue;
    }

    if (line.trim() !== "" && !line.trim().startsWith("#")) {
      break;
    }
  }

  return patterns;
}

function readWorkspacePackageNames(root) {
  const packageNames = new Set();

  for (const pattern of readWorkspacePackagePatterns(root)) {
    if (!pattern.endsWith("/*")) {
      throw new Error(`Unsupported pnpm workspace package pattern: ${pattern}`);
    }

    const workspaceDirectory = join(root, pattern.slice(0, -2));
    for (const entry of readdirSync(workspaceDirectory, { withFileTypes: true })) {
      if (!entry.isDirectory()) {
        continue;
      }

      const packageJsonPath = join(workspaceDirectory, entry.name, "package.json");
      if (!existsSync(packageJsonPath)) {
        continue;
      }

      const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
      if (typeof packageJson.name === "string") {
        packageNames.add(packageJson.name);
      }
    }
  }

  return packageNames;
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
    "node-server-runtime": "apps/api-worker/src/node-server.ts",
    "node-worker-runtime": "apps/api-worker/src/node-worker.ts",
  },
  external: isExternalImport,
  platform: "node",
  output: {
    dir: "apps/api-worker/dist/node-runtime",
    entryFileNames: "[name].js",
    format: "esm",
    sourcemap: !isProductionBuild,
  },
  resolve: {
    conditionNames: ["node", "import", "default"],
    mainFields: ["module", "main"],
  },
  tsconfig: "./tsconfig.json",
};
