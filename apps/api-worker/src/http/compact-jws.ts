import type { JsonObject } from "@credtrail/core-domain";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { asJsonObject } from "../utils/value-parsers";

export const parseCompactJwsPayloadObject = (compactJws: string): JsonObject | null => {
  try {
    return asJsonObject(decodeJwt(compactJws));
  } catch {
    return null;
  }
};

export const parseCompactJwsHeaderObject = (compactJws: string): JsonObject | null => {
  try {
    return asJsonObject(decodeProtectedHeader(compactJws));
  } catch {
    return null;
  }
};
