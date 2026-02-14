interface Ob3ResponseContext {
  header(name: string, value: string): void;
  json(payload: unknown, status?: number): Response;
}

interface OAuthErrorResponse {
  error: string;
  error_description?: string | undefined;
}

interface Ob3ErrorResponses<ContextType extends Ob3ResponseContext> {
  oauthErrorJson: (
    context: ContextType,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
  ) => Response;
  oauthTokenErrorJson: (
    context: ContextType,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
    includeWwwAuthenticate?: boolean,
  ) => Response;
  oauthTokenSuccessJson: (
    context: ContextType,
    payload: {
      access_token: string;
      token_type: 'Bearer';
      expires_in: number;
      scope: string;
      refresh_token?: string | undefined;
    },
  ) => Response;
  ob3ErrorJson: (
    context: ContextType,
    status: 400 | 401 | 403 | 404 | 500,
    description: string,
    options?: {
      includeWwwAuthenticate?: boolean;
    },
  ) => Response;
}

export const createOb3ErrorResponses = <ContextType extends Ob3ResponseContext>(): Ob3ErrorResponses<ContextType> => {
  const oauthErrorJson = (
    context: ContextType,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
  ): Response => {
    return context.json(
      {
        error,
        ...(errorDescription === undefined ? {} : { error_description: errorDescription }),
      } satisfies OAuthErrorResponse,
      status,
    );
  };

  const oauthTokenErrorJson = (
    context: ContextType,
    status: 400 | 401 | 403 | 500,
    error: string,
    errorDescription?: string,
    includeWwwAuthenticate = false,
  ): Response => {
    context.header('Cache-Control', 'no-store');
    context.header('Pragma', 'no-cache');

    if (includeWwwAuthenticate) {
      context.header('WWW-Authenticate', 'Basic realm="OAuth2 Token Endpoint"');
    }

    return oauthErrorJson(context, status, error, errorDescription);
  };

  const oauthTokenSuccessJson = (
    context: ContextType,
    payload: {
      access_token: string;
      token_type: 'Bearer';
      expires_in: number;
      scope: string;
      refresh_token?: string | undefined;
    },
  ): Response => {
    context.header('Cache-Control', 'no-store');
    context.header('Pragma', 'no-cache');
    return context.json(payload);
  };

  const ob3ErrorJson = (
    context: ContextType,
    status: 400 | 401 | 403 | 404 | 500,
    description: string,
    options?: {
      includeWwwAuthenticate?: boolean;
    },
  ): Response => {
    if (options?.includeWwwAuthenticate === true) {
      context.header('WWW-Authenticate', 'Bearer realm="Open Badges API"');
    }

    return context.json(
      {
        imsx_codeMajor: 'failure',
        imsx_severity: 'error',
        imsx_description: description,
      },
      status,
    );
  };

  return {
    oauthErrorJson,
    oauthTokenErrorJson,
    oauthTokenSuccessJson,
    ob3ErrorJson,
  };
};
