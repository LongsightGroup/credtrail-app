import type {
  LTIClient,
  LTIDeployment,
  LTIDynamicRegistrationSession,
  LTILaunchConfig,
  LTISession,
  LTIStorage,
} from "@lti-tool/core";
import {
  consumeLtiLaunchNonce,
  deleteLtiDynamicRegistrationSessionById,
  findLtiDeploymentByIssuerClientDeployment,
  findLtiDynamicRegistrationSessionById,
  findLtiLaunchSessionById,
  listLtiDeploymentsForIssuer,
  listLtiIssuerRegistrations,
  storeLtiLaunchNonce,
  upsertLtiDeployment,
  upsertLtiDynamicRegistrationSession,
  upsertLtiIssuerRegistration,
  upsertLtiLaunchSession,
  type LtiIssuerRegistrationRecord,
  type SqlDatabase,
} from "@credtrail/db";
import { normalizeLtiIssuer } from "./lti-helpers";

const SESSION_TTL_SECONDS = 60 * 60;

const addSeconds = (seconds: number): string => {
  return new Date(Date.now() + seconds * 1000).toISOString();
};

const requirePlatformEndpoints = (
  registration: LtiIssuerRegistrationRecord,
): {
  tokenUrl: string;
  jwksUrl: string;
} => {
  if (registration.tokenEndpoint === null) {
    throw new Error(`LTI issuer "${registration.issuer}" is missing token endpoint`);
  }

  if (registration.platformJwksEndpoint === null) {
    throw new Error(`LTI issuer "${registration.issuer}" is missing platform JWKS endpoint`);
  }

  return {
    tokenUrl: registration.tokenEndpoint,
    jwksUrl: registration.platformJwksEndpoint,
  };
};

const toClient = async (
  db: SqlDatabase,
  registration: LtiIssuerRegistrationRecord,
): Promise<LTIClient> => {
  const endpoints = requirePlatformEndpoints(registration);
  const deployments = await listLtiDeploymentsForIssuer(db, registration.issuer);

  return {
    id: normalizeLtiIssuer(registration.issuer),
    name: registration.issuer,
    iss: normalizeLtiIssuer(registration.issuer),
    clientId: registration.clientId,
    authUrl: registration.authorizationEndpoint,
    tokenUrl: endpoints.tokenUrl,
    jwksUrl: endpoints.jwksUrl,
    deployments: deployments.map((deployment) => ({
      id: deployment.id,
      deploymentId: deployment.deploymentId,
      ...(deployment.name === null ? {} : { name: deployment.name }),
      ...(deployment.description === null ? {} : { description: deployment.description }),
    })),
  };
};

export class CredTrailLtiStorage implements LTIStorage {
  constructor(
    private readonly db: SqlDatabase,
    private readonly options: {
      defaultTenantId?: string | undefined;
    } = {},
  ) {}

  async listClients(): Promise<Omit<LTIClient, "deployments">[]> {
    const registrations = await listLtiIssuerRegistrations(this.db);
    const clients = await Promise.all(
      registrations
        .filter(
          (registration) =>
            registration.tokenEndpoint !== null && registration.platformJwksEndpoint !== null,
        )
        .map((registration) => toClient(this.db, registration)),
    );

    return clients.map(({ deployments: _deployments, ...client }) => client);
  }

  async getClientById(clientId: string): Promise<LTIClient | undefined> {
    const normalizedClientId = normalizeLtiIssuer(clientId);
    const registrations = await listLtiIssuerRegistrations(this.db);
    const registration = registrations.find(
      (candidate) => normalizeLtiIssuer(candidate.issuer) === normalizedClientId,
    );

    if (registration === undefined) {
      return undefined;
    }

    return toClient(this.db, registration);
  }

  async addClient(client: Omit<LTIClient, "id" | "deployments">): Promise<string> {
    const tenantId = this.options.defaultTenantId;

    if (tenantId === undefined) {
      throw new Error("defaultTenantId is required to add LTI clients through storage");
    }

    await upsertLtiIssuerRegistration(this.db, {
      issuer: client.iss,
      tenantId,
      authorizationEndpoint: client.authUrl,
      clientId: client.clientId,
      platformJwksEndpoint: client.jwksUrl,
      tokenEndpoint: client.tokenUrl,
      allowUnsignedIdToken: false,
    });

    return normalizeLtiIssuer(client.iss);
  }

  async updateClient(
    clientId: string,
    client: Partial<Omit<LTIClient, "id" | "deployments">>,
  ): Promise<void> {
    const existing = await this.getClientById(clientId);

    if (existing === undefined) {
      throw new Error(`LTI client not found: ${clientId}`);
    }

    const tenantId = this.options.defaultTenantId;

    if (tenantId === undefined) {
      throw new Error("defaultTenantId is required to update LTI clients through storage");
    }

    await upsertLtiIssuerRegistration(this.db, {
      issuer: client.iss ?? existing.iss,
      tenantId,
      authorizationEndpoint: client.authUrl ?? existing.authUrl,
      clientId: client.clientId ?? existing.clientId,
      platformJwksEndpoint: client.jwksUrl ?? existing.jwksUrl,
      tokenEndpoint: client.tokenUrl ?? existing.tokenUrl,
      allowUnsignedIdToken: false,
    });
  }

  async deleteClient(_clientId: string): Promise<void> {
    throw new Error("Deleting LTI clients through CredTrailLtiStorage is not implemented");
  }

  async listDeployments(clientId: string): Promise<LTIDeployment[]> {
    const deployments = await listLtiDeploymentsForIssuer(this.db, clientId);
    return deployments.map((deployment) => ({
      id: deployment.id,
      deploymentId: deployment.deploymentId,
      ...(deployment.name === null ? {} : { name: deployment.name }),
      ...(deployment.description === null ? {} : { description: deployment.description }),
    }));
  }

  async getDeployment(clientId: string, deploymentId: string): Promise<LTIDeployment | undefined> {
    const client = await this.getClientById(clientId);

    if (client === undefined) {
      return undefined;
    }

    const deployment = await findLtiDeploymentByIssuerClientDeployment(this.db, {
      issuer: client.iss,
      clientId: client.clientId,
      deploymentId,
    });

    if (deployment === null) {
      return undefined;
    }

    return {
      id: deployment.id,
      deploymentId: deployment.deploymentId,
      ...(deployment.name === null ? {} : { name: deployment.name }),
      ...(deployment.description === null ? {} : { description: deployment.description }),
    };
  }

  async addDeployment(clientId: string, deployment: Omit<LTIDeployment, "id">): Promise<string> {
    const client = await this.getClientById(clientId);

    if (client === undefined) {
      throw new Error(`LTI client not found: ${clientId}`);
    }

    const created = await upsertLtiDeployment(this.db, {
      issuer: client.iss,
      clientId: client.clientId,
      deploymentId: deployment.deploymentId,
      name: deployment.name,
      description: deployment.description,
    });

    return created.id;
  }

  async updateDeployment(
    clientId: string,
    deploymentId: string,
    deployment: Partial<LTIDeployment>,
  ): Promise<void> {
    const client = await this.getClientById(clientId);

    if (client === undefined) {
      throw new Error(`LTI client not found: ${clientId}`);
    }

    await upsertLtiDeployment(this.db, {
      issuer: client.iss,
      clientId: client.clientId,
      deploymentId,
      name: deployment.name,
      description: deployment.description,
    });
  }

  async deleteDeployment(_clientId: string, _deploymentId: string): Promise<void> {
    throw new Error("Deleting LTI deployments through CredTrailLtiStorage is not implemented");
  }

  async getSession(sessionId: string): Promise<LTISession | undefined> {
    const session = await findLtiLaunchSessionById(this.db, sessionId);

    if (session === null) {
      return undefined;
    }

    return JSON.parse(session.dataJson) as LTISession;
  }

  async addSession(session: LTISession): Promise<string> {
    await upsertLtiLaunchSession(this.db, {
      id: session.id,
      issuer: session.platform.issuer,
      clientId: session.platform.clientId,
      deploymentId: session.platform.deploymentId,
      dataJson: JSON.stringify(session),
      expiresAt: addSeconds(SESSION_TTL_SECONDS),
    });

    return session.id;
  }

  async storeNonce(nonce: string, expiresAt: Date): Promise<void> {
    await storeLtiLaunchNonce(this.db, nonce, expiresAt.toISOString());
  }

  async validateNonce(nonce: string): Promise<boolean> {
    return consumeLtiLaunchNonce(this.db, nonce, new Date().toISOString());
  }

  async getLaunchConfig(
    iss: string,
    clientId: string,
    deploymentId: string,
  ): Promise<LTILaunchConfig | undefined> {
    const normalizedIssuer = normalizeLtiIssuer(iss);
    const registrations = await listLtiIssuerRegistrations(this.db);
    const registration = registrations.find(
      (candidate) =>
        normalizeLtiIssuer(candidate.issuer) === normalizedIssuer &&
        candidate.clientId === clientId,
    );

    if (registration === undefined) {
      return undefined;
    }

    const endpoints = requirePlatformEndpoints(registration);
    const deployment =
      (await findLtiDeploymentByIssuerClientDeployment(this.db, {
        issuer: normalizedIssuer,
        clientId,
        deploymentId,
      })) ??
      (deploymentId === "default"
        ? null
        : await findLtiDeploymentByIssuerClientDeployment(this.db, {
            issuer: normalizedIssuer,
            clientId,
            deploymentId: "default",
          }));

    if (deployment === null) {
      return undefined;
    }

    return {
      iss: normalizedIssuer,
      clientId,
      deploymentId: deployment.deploymentId,
      authUrl: registration.authorizationEndpoint,
      tokenUrl: endpoints.tokenUrl,
      jwksUrl: endpoints.jwksUrl,
    };
  }

  async saveLaunchConfig(launchConfig: LTILaunchConfig): Promise<void> {
    const tenantId = this.options.defaultTenantId;

    if (tenantId === undefined) {
      throw new Error("defaultTenantId is required to save LTI launch configs");
    }

    await upsertLtiIssuerRegistration(this.db, {
      issuer: launchConfig.iss,
      tenantId,
      authorizationEndpoint: launchConfig.authUrl,
      clientId: launchConfig.clientId,
      platformJwksEndpoint: launchConfig.jwksUrl,
      tokenEndpoint: launchConfig.tokenUrl,
      allowUnsignedIdToken: false,
    });
    await upsertLtiDeployment(this.db, {
      issuer: launchConfig.iss,
      clientId: launchConfig.clientId,
      deploymentId: launchConfig.deploymentId,
    });
  }

  async setRegistrationSession(
    sessionId: string,
    session: LTIDynamicRegistrationSession,
  ): Promise<void> {
    await upsertLtiDynamicRegistrationSession(this.db, {
      id: sessionId,
      dataJson: JSON.stringify(session),
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  }

  async getRegistrationSession(
    sessionId: string,
  ): Promise<LTIDynamicRegistrationSession | undefined> {
    const session = await findLtiDynamicRegistrationSessionById(this.db, sessionId);

    if (session === null) {
      return undefined;
    }

    return JSON.parse(session.dataJson) as LTIDynamicRegistrationSession;
  }

  async deleteRegistrationSession(sessionId: string): Promise<void> {
    await deleteLtiDynamicRegistrationSessionById(this.db, sessionId);
  }
}
