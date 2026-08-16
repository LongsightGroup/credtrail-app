import type { AppContext } from "../app";

type JsonErrorStatus = 400 | 401 | 403 | 404 | 408 | 409 | 422 | 500 | 501 | 502 | 503;

export const jsonError = (c: AppContext, status: JsonErrorStatus, message: string): Response => {
  return c.json({ error: message }, status);
};
