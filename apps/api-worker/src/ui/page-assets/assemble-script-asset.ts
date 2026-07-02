import type { ScriptPageAssetBuildSource, ScriptPageAssetSource } from "./build-registry";

/** Reads an authored JavaScript fragment file by registry path. */
export type ScriptSourceReader = (sourcePath: string) => string;

const readScriptSource = (
  source: ScriptPageAssetSource,
  readSource: ScriptSourceReader,
): string => {
  return typeof source === "string" ? readSource(source) : source.body;
};

/** Assembles ordered JavaScript fragments into one private browser script. */
export const assembleScriptAsset = (
  source: ScriptPageAssetBuildSource,
  readSource: ScriptSourceReader,
): string => {
  const body = source.sources
    .map((scriptSource) => readScriptSource(scriptSource, readSource))
    .join("\n");

  return `(() => {\n${body}\n})();`;
};
