import { readFileSync } from "node:fs";
import { join } from "node:path";

const parseEnvFile = (contents) => {
  const values = new Map();

  for (const rawLine of contents.split(/\r?\n/g)) {
    const line = rawLine.trim();

    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }

    const separatorIndex = line.indexOf("=");

    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim();
    let value = line.slice(separatorIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    values.set(key, value);
  }

  return values;
};

export const loadLocalDevEnv = (cwd = process.cwd()) => {
  try {
    const envPath = join(cwd, ".dev.vars.local");
    const values = parseEnvFile(readFileSync(envPath, "utf8"));

    for (const [key, value] of values.entries()) {
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      throw error;
    }
  }
};

export const requireEnv = (name) => {
  const value = process.env[name]?.trim();

  if (value === undefined || value.length === 0) {
    throw new Error(`${name} is required`);
  }

  return value;
};
