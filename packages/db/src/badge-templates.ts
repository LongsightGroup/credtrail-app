import { createPrefixedId } from "./shared-helpers";
import { ensureInstitutionOrgUnitForTenant, findTenantOrgUnitById } from "./tenant-org-units";
import type { SqlDatabase, SqlQueryResult, SqlRunResult } from "./tenant-scope";

export interface UpsertBadgeTemplateByIdInput {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description?: string | undefined;
  criteriaUri?: string | undefined;
  imageUri?: string | undefined;
  createdByUserId?: string | undefined;
  ownerOrgUnitId?: string | undefined;
  governanceMetadataJson?: string | undefined;
}

export interface BadgeTemplateRecord {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
  isArchived: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateBadgeTemplateInput {
  tenantId: string;
  slug: string;
  title: string;
  description?: string | undefined;
  criteriaUri?: string | undefined;
  imageUri?: string | undefined;
  createdByUserId?: string | undefined;
  ownerOrgUnitId?: string | undefined;
  governanceMetadataJson?: string | undefined;
}

export interface ListBadgeTemplatesInput {
  tenantId: string;
  includeArchived: boolean;
}

export interface UpdateBadgeTemplateInput {
  tenantId: string;
  id: string;
  slug?: string | undefined;
  title?: string | undefined;
  description?: string | null | undefined;
  criteriaUri?: string | null | undefined;
  imageUri?: string | null | undefined;
}

export interface SetBadgeTemplateArchiveStateInput {
  tenantId: string;
  id: string;
  isArchived: boolean;
}

export type BadgeTemplateOwnershipReasonCode =
  | "initial_assignment"
  | "administrative_transfer"
  | "reorganization"
  | "governance_policy_update"
  | "other";

export interface BadgeTemplateOwnershipEventRecord {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
  createdAt: string;
}

export interface ListBadgeTemplateOwnershipEventsInput {
  tenantId: string;
  badgeTemplateId: string;
  limit?: number | undefined;
}

export interface TransferBadgeTemplateOwnershipInput {
  tenantId: string;
  badgeTemplateId: string;
  toOrgUnitId: string;
  reasonCode: Exclude<BadgeTemplateOwnershipReasonCode, "initial_assignment">;
  reason?: string | undefined;
  governanceMetadataJson?: string | undefined;
  transferredByUserId?: string | undefined;
  transferredAt: string;
}

export interface TransferBadgeTemplateOwnershipResult {
  status: "transferred" | "already_owned";
  template: BadgeTemplateRecord;
  event: BadgeTemplateOwnershipEventRecord | null;
}

interface BadgeTemplateRow {
  id: string;
  tenantId: string;
  slug: string;
  title: string;
  description: string | null;
  criteriaUri: string | null;
  imageUri: string | null;
  createdByUserId: string | null;
  ownerOrgUnitId: string;
  governanceMetadataJson: string | null;
  isArchived: number | boolean;
  createdAt: string;
  updatedAt: string;
}

interface BadgeTemplateOwnershipEventRow {
  id: string;
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
  createdAt: string;
}

const BADGE_TEMPLATE_OWNERSHIP_REASON_CODES = new Set<BadgeTemplateOwnershipReasonCode>([
  "initial_assignment",
  "administrative_transfer",
  "reorganization",
  "governance_policy_update",
  "other",
]);

const mapBadgeTemplateRow = (row: BadgeTemplateRow): BadgeTemplateRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    slug: row.slug,
    title: row.title,
    description: row.description,
    criteriaUri: row.criteriaUri,
    imageUri: row.imageUri,
    createdByUserId: row.createdByUserId,
    ownerOrgUnitId: row.ownerOrgUnitId,
    governanceMetadataJson: row.governanceMetadataJson,
    isArchived: row.isArchived === 1 || row.isArchived === true,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
};

const mapBadgeTemplateOwnershipEventRow = (
  row: BadgeTemplateOwnershipEventRow,
): BadgeTemplateOwnershipEventRecord => {
  return {
    id: row.id,
    tenantId: row.tenantId,
    badgeTemplateId: row.badgeTemplateId,
    fromOrgUnitId: row.fromOrgUnitId,
    toOrgUnitId: row.toOrgUnitId,
    reasonCode: row.reasonCode,
    reason: row.reason,
    governanceMetadataJson: row.governanceMetadataJson,
    transferredByUserId: row.transferredByUserId,
    transferredAt: row.transferredAt,
    createdAt: row.createdAt,
  };
};

interface CreateBadgeTemplateOwnershipEventInput {
  tenantId: string;
  badgeTemplateId: string;
  fromOrgUnitId: string | null;
  toOrgUnitId: string;
  reasonCode: BadgeTemplateOwnershipReasonCode;
  reason: string | null;
  governanceMetadataJson: string | null;
  transferredByUserId: string | null;
  transferredAt: string;
}

const createBadgeTemplateOwnershipEvent = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateOwnershipEventInput,
): Promise<BadgeTemplateOwnershipEventRecord> => {
  const eventId = createPrefixedId("btoe");
  const insertStatement = (): Promise<SqlRunResult> =>
    db
      .prepare(
        `
        INSERT INTO badge_template_ownership_events (
          id,
          tenant_id,
          badge_template_id,
          from_org_unit_id,
          to_org_unit_id,
          reason_code,
          reason,
          governance_metadata_json,
          transferred_by_user_id,
          transferred_at,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      )
      .bind(
        eventId,
        input.tenantId,
        input.badgeTemplateId,
        input.fromOrgUnitId,
        input.toOrgUnitId,
        input.reasonCode,
        input.reason,
        input.governanceMetadataJson,
        input.transferredByUserId,
        input.transferredAt,
        input.transferredAt,
      )
      .run();

  const findStatement = (): Promise<BadgeTemplateOwnershipEventRow | null> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          from_org_unit_id AS fromOrgUnitId,
          to_org_unit_id AS toOrgUnitId,
          reason_code AS reasonCode,
          reason,
          governance_metadata_json AS governanceMetadataJson,
          transferred_by_user_id AS transferredByUserId,
          transferred_at AS transferredAt,
          created_at AS createdAt
        FROM badge_template_ownership_events
        WHERE id = ?
        LIMIT 1
      `,
      )
      .bind(eventId)
      .first<BadgeTemplateOwnershipEventRow>();

  await insertStatement();

  const eventRow = await findStatement();

  if (eventRow === null) {
    throw new Error(`Unable to load badge template ownership event ${eventId} after insert`);
  }

  return mapBadgeTemplateOwnershipEventRow(eventRow);
};

export const upsertBadgeTemplateById = async (
  db: SqlDatabase,
  input: UpsertBadgeTemplateByIdInput,
): Promise<BadgeTemplateRecord> => {
  const nowIso = new Date().toISOString();
  const previous = await findBadgeTemplateById(db, input.tenantId, input.id);

  if (
    previous !== null &&
    input.ownerOrgUnitId !== undefined &&
    input.ownerOrgUnitId !== previous.ownerOrgUnitId
  ) {
    throw new Error("Badge template ownership changes must use transferBadgeTemplateOwnership");
  }

  const fallbackOwnerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
  const ownerOrgUnitId = previous?.ownerOrgUnitId ?? input.ownerOrgUnitId ?? fallbackOwnerOrgUnitId;
  const ownerOrgUnit = await findTenantOrgUnitById(db, input.tenantId, ownerOrgUnitId);

  if (ownerOrgUnit === null) {
    throw new Error(`Org unit ${ownerOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  const governanceMetadataJson =
    previous?.governanceMetadataJson ??
    input.governanceMetadataJson ??
    '{"stability":"institution_registry"}';

  await db
    .prepare(
      `
      INSERT INTO badge_templates (
        id,
        tenant_id,
        slug,
        title,
        description,
        criteria_uri,
        image_uri,
        created_by_user_id,
        owner_org_unit_id,
        governance_metadata_json,
        is_archived,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
      ON CONFLICT (id)
      DO UPDATE SET
        tenant_id = excluded.tenant_id,
        slug = excluded.slug,
        title = excluded.title,
        description = excluded.description,
        criteria_uri = excluded.criteria_uri,
        image_uri = excluded.image_uri,
        created_by_user_id = excluded.created_by_user_id,
        owner_org_unit_id = badge_templates.owner_org_unit_id,
        governance_metadata_json = badge_templates.governance_metadata_json,
        is_archived = 0,
        updated_at = excluded.updated_at
    `,
    )
    .bind(
      input.id,
      input.tenantId,
      input.slug,
      input.title,
      input.description ?? null,
      input.criteriaUri ?? null,
      input.imageUri ?? null,
      input.createdByUserId ?? null,
      ownerOrgUnitId,
      governanceMetadataJson,
      nowIso,
      nowIso,
    )
    .run();

  const template = await findBadgeTemplateById(db, input.tenantId, input.id);

  if (template === null) {
    throw new Error(`Unable to upsert badge template "${input.id}"`);
  }

  if (previous === null) {
    await createBadgeTemplateOwnershipEvent(db, {
      tenantId: input.tenantId,
      badgeTemplateId: template.id,
      fromOrgUnitId: null,
      toOrgUnitId: template.ownerOrgUnitId,
      reasonCode: "initial_assignment",
      reason: "Badge template ownership assigned at creation",
      governanceMetadataJson: template.governanceMetadataJson,
      transferredByUserId: template.createdByUserId,
      transferredAt: template.createdAt,
    });
  }

  return template;
};

export const createBadgeTemplate = async (
  db: SqlDatabase,
  input: CreateBadgeTemplateInput,
): Promise<BadgeTemplateRecord> => {
  const id = createPrefixedId("bt");
  const nowIso = new Date().toISOString();
  const fallbackOwnerOrgUnitId = await ensureInstitutionOrgUnitForTenant(db, input.tenantId);
  const ownerOrgUnitId = input.ownerOrgUnitId ?? fallbackOwnerOrgUnitId;
  const ownerOrgUnit = await findTenantOrgUnitById(db, input.tenantId, ownerOrgUnitId);

  if (ownerOrgUnit === null) {
    throw new Error(`Org unit ${ownerOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  const governanceMetadataJson =
    input.governanceMetadataJson ?? '{"stability":"institution_registry"}';

  await db
    .prepare(
      `
      INSERT INTO badge_templates (
        id,
        tenant_id,
        slug,
        title,
        description,
        criteria_uri,
        image_uri,
        created_by_user_id,
        owner_org_unit_id,
        governance_metadata_json,
        is_archived,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `,
    )
    .bind(
      id,
      input.tenantId,
      input.slug,
      input.title,
      input.description ?? null,
      input.criteriaUri ?? null,
      input.imageUri ?? null,
      input.createdByUserId ?? null,
      ownerOrgUnitId,
      governanceMetadataJson,
      nowIso,
      nowIso,
    )
    .run();

  const template: BadgeTemplateRecord = {
    id,
    tenantId: input.tenantId,
    slug: input.slug,
    title: input.title,
    description: input.description ?? null,
    criteriaUri: input.criteriaUri ?? null,
    imageUri: input.imageUri ?? null,
    createdByUserId: input.createdByUserId ?? null,
    ownerOrgUnitId,
    governanceMetadataJson,
    isArchived: false,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  await createBadgeTemplateOwnershipEvent(db, {
    tenantId: input.tenantId,
    badgeTemplateId: template.id,
    fromOrgUnitId: null,
    toOrgUnitId: template.ownerOrgUnitId,
    reasonCode: "initial_assignment",
    reason: "Badge template ownership assigned at creation",
    governanceMetadataJson: template.governanceMetadataJson,
    transferredByUserId: template.createdByUserId,
    transferredAt: template.createdAt,
  });

  return template;
};

export const listBadgeTemplates = async (
  db: SqlDatabase,
  input: ListBadgeTemplatesInput,
): Promise<BadgeTemplateRecord[]> => {
  const query = input.includeArchived
    ? `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
      ORDER BY created_at DESC
    `
    : `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
        AND is_archived = 0
      ORDER BY created_at DESC
    `;

  const result = await db.prepare(query).bind(input.tenantId).all<BadgeTemplateRow>();
  const rows = result.results;

  return rows.map((row) => mapBadgeTemplateRow(row));
};

export const findBadgeTemplateById = async (
  db: SqlDatabase,
  tenantId: string,
  badgeTemplateId: string,
): Promise<BadgeTemplateRecord | null> => {
  const row = await db
    .prepare(
      `
      SELECT
        id,
        tenant_id AS tenantId,
        slug,
        title,
        description,
        criteria_uri AS criteriaUri,
        image_uri AS imageUri,
        created_by_user_id AS createdByUserId,
        owner_org_unit_id AS ownerOrgUnitId,
        governance_metadata_json AS governanceMetadataJson,
        is_archived AS isArchived,
        created_at AS createdAt,
        updated_at AS updatedAt
      FROM badge_templates
      WHERE tenant_id = ?
        AND id = ?
      LIMIT 1
    `,
    )
    .bind(tenantId, badgeTemplateId)
    .first<BadgeTemplateRow>();

  if (row === null) {
    return null;
  }

  return mapBadgeTemplateRow(row);
};

export const updateBadgeTemplate = async (
  db: SqlDatabase,
  input: UpdateBadgeTemplateInput,
): Promise<BadgeTemplateRecord | null> => {
  const setClauses: string[] = [];
  const params: (string | null)[] = [];

  if (input.slug !== undefined) {
    setClauses.push("slug = ?");
    params.push(input.slug);
  }

  if (input.title !== undefined) {
    setClauses.push("title = ?");
    params.push(input.title);
  }

  if (input.description !== undefined) {
    setClauses.push("description = ?");
    params.push(input.description);
  }

  if (input.criteriaUri !== undefined) {
    setClauses.push("criteria_uri = ?");
    params.push(input.criteriaUri);
  }

  if (input.imageUri !== undefined) {
    setClauses.push("image_uri = ?");
    params.push(input.imageUri);
  }

  if (setClauses.length === 0) {
    throw new Error("No badge template fields were provided for update");
  }

  const updatedAt = new Date().toISOString();
  const sql = `
    UPDATE badge_templates
    SET ${setClauses.join(", ")},
        updated_at = ?
    WHERE tenant_id = ?
      AND id = ?
  `;

  await db
    .prepare(sql)
    .bind(...params, updatedAt, input.tenantId, input.id)
    .run();

  return findBadgeTemplateById(db, input.tenantId, input.id);
};

export const setBadgeTemplateArchivedState = async (
  db: SqlDatabase,
  input: SetBadgeTemplateArchiveStateInput,
): Promise<BadgeTemplateRecord | null> => {
  const updatedAt = new Date().toISOString();

  await db
    .prepare(
      `
      UPDATE badge_templates
      SET is_archived = ?,
          updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(input.isArchived ? 1 : 0, updatedAt, input.tenantId, input.id)
    .run();

  return findBadgeTemplateById(db, input.tenantId, input.id);
};

export const listBadgeTemplateOwnershipEvents = async (
  db: SqlDatabase,
  input: ListBadgeTemplateOwnershipEventsInput,
): Promise<BadgeTemplateOwnershipEventRecord[]> => {
  const queryLimit = Math.max(1, Math.min(input.limit ?? 100, 500));
  const listStatement = (): Promise<SqlQueryResult<BadgeTemplateOwnershipEventRow>> =>
    db
      .prepare(
        `
        SELECT
          id,
          tenant_id AS tenantId,
          badge_template_id AS badgeTemplateId,
          from_org_unit_id AS fromOrgUnitId,
          to_org_unit_id AS toOrgUnitId,
          reason_code AS reasonCode,
          reason,
          governance_metadata_json AS governanceMetadataJson,
          transferred_by_user_id AS transferredByUserId,
          transferred_at AS transferredAt,
          created_at AS createdAt
        FROM badge_template_ownership_events
        WHERE tenant_id = ?
          AND badge_template_id = ?
        ORDER BY transferred_at DESC, created_at DESC, id DESC
        LIMIT ?
      `,
      )
      .bind(input.tenantId, input.badgeTemplateId, queryLimit)
      .all<BadgeTemplateOwnershipEventRow>();

  let result: SqlQueryResult<BadgeTemplateOwnershipEventRow>;

  result = await listStatement();

  return result.results.map((row) => mapBadgeTemplateOwnershipEventRow(row));
};

export const transferBadgeTemplateOwnership = async (
  db: SqlDatabase,
  input: TransferBadgeTemplateOwnershipInput,
): Promise<TransferBadgeTemplateOwnershipResult> => {
  const transferredAtMs = Date.parse(input.transferredAt);

  if (!Number.isFinite(transferredAtMs)) {
    throw new Error("transferredAt must be a valid ISO timestamp");
  }

  if (!BADGE_TEMPLATE_OWNERSHIP_REASON_CODES.has(input.reasonCode)) {
    throw new Error(`Unsupported badge template ownership reason code: ${input.reasonCode}`);
  }

  const template = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (template === null) {
    throw new Error(
      `Badge template ${input.badgeTemplateId} not found for tenant ${input.tenantId}`,
    );
  }

  const toOrgUnit = await findTenantOrgUnitById(db, input.tenantId, input.toOrgUnitId);

  if (toOrgUnit === null) {
    throw new Error(`Org unit ${input.toOrgUnitId} not found for tenant ${input.tenantId}`);
  }

  if (template.ownerOrgUnitId === input.toOrgUnitId) {
    return {
      status: "already_owned",
      template,
      event: null,
    };
  }

  const normalizedReason = input.reason?.trim();
  const reason =
    normalizedReason === undefined || normalizedReason.length === 0 ? null : normalizedReason;
  const governanceMetadataJson = input.governanceMetadataJson ?? template.governanceMetadataJson;

  await db
    .prepare(
      `
      UPDATE badge_templates
      SET owner_org_unit_id = ?,
          governance_metadata_json = ?,
          updated_at = ?
      WHERE tenant_id = ?
        AND id = ?
    `,
    )
    .bind(
      input.toOrgUnitId,
      governanceMetadataJson,
      input.transferredAt,
      input.tenantId,
      input.badgeTemplateId,
    )
    .run();

  const updatedTemplate = await findBadgeTemplateById(db, input.tenantId, input.badgeTemplateId);

  if (updatedTemplate === null) {
    throw new Error(
      `Unable to load badge template ${input.badgeTemplateId} after ownership transfer`,
    );
  }

  const event = await createBadgeTemplateOwnershipEvent(db, {
    tenantId: input.tenantId,
    badgeTemplateId: input.badgeTemplateId,
    fromOrgUnitId: template.ownerOrgUnitId,
    toOrgUnitId: input.toOrgUnitId,
    reasonCode: input.reasonCode,
    reason,
    governanceMetadataJson,
    transferredByUserId: input.transferredByUserId ?? null,
    transferredAt: input.transferredAt,
  });

  return {
    status: "transferred",
    template: updatedTemplate,
    event,
  };
};
