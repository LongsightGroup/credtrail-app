export class HttpErrorResponse extends Error {
  public readonly statusCode: 400 | 404 | 409 | 422 | 500 | 502 | 503;

  public readonly payload: {
    error: string;
    did?: string | undefined;
  };

  public constructor(
    statusCode: 400 | 404 | 409 | 422 | 500 | 502 | 503,
    payload: {
      error: string;
      did?: string | undefined;
    },
  ) {
    super(payload.error);
    this.statusCode = statusCode;
    this.payload = payload;
  }
}
