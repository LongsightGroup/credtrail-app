import type { ScriptPageAssetBuildSource } from "./build-registry";

/** Reads an authored JavaScript source file by registry path. */
export type ScriptSourceReader = (sourcePath: string) => string;

/** Assembles an ordered browser JavaScript asset from authored source files. */
export const assembleScriptAsset = (
  source: ScriptPageAssetBuildSource,
  readSource: ScriptSourceReader,
): string => {
  const body = source.sources.map((sourcePath) => readSource(sourcePath)).join("\n");

  return source.wrapper === "iife" ? `(() => {\n${body}\n})();` : body;
};
