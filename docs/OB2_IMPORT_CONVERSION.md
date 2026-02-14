# OB2 Import Conversion

`badging-b21` adds a foundational OB2-to-OB3 import converter.

## Endpoint

`POST /v1/tenants/:tenantId/migrations/ob2/convert`

`POST /v1/tenants/:tenantId/migrations/ob2/dry-run`

`POST /v1/tenants/:tenantId/migrations/ob2/batch-upload?dryRun=true|false`

Auth: tenant session with issuer role (`owner`, `admin`, or `issuer`).

## Request

Provide at least one source:

- `ob2Assertion` JSON
- `bakedBadgeImage` (base64 PNG or `data:image/png;base64,...`)

Optional companion objects for URL-referenced OB2 data:

- `ob2BadgeClass`
- `ob2Issuer`

Batch upload endpoint (`/batch-upload`):

- Content type: `multipart/form-data`
- File field name: `file`
- Supported file types: `.json`, `.csv`
- Query param:
- `dryRun=true` (default) validates and previews only
- `dryRun=false` enqueues valid rows as `import_migration_batch` jobs

## Response

The endpoint returns:

- `extractedFromBakedBadge` when `bakedBadgeImage` is supplied
- `conversion` with normalized import candidates:
- `createBadgeTemplateRequest`
- `manualIssueRequest`
- `issueOptions`
- `sourceMetadata`
- `warnings`

If the baked PNG only contains an assertion URL, extraction succeeds and `conversion` is `null` until full assertion JSON is provided.

## Dry-run Validation Report

`/dry-run` always responds with a validation report that includes:

- `status`: `valid` or `invalid`
- `validationReport.errors`: blocking issues
- `validationReport.warnings`: non-blocking conversion warnings
- `validationReport.diffPreview`: simulated create/update impact

The diff preview currently models:

- badge template create/update action and changed fields
- learner profile reuse/create impact
- assertion issue operation summary (create/update counts)

## Baked PNG Support

The converter extracts Open Badges payloads from PNG text chunks:

- `tEXt`
- `iTXt`
- `zTXt`

Accepted keywords: `openbadges`, `openbadge`.

## CSV Columns

Batch CSV files support these columns (case/format-insensitive):

- `ob2Assertion` (or `assertion`)
- `ob2BadgeClass` (or `badgeClass` / `badge`)
- `ob2Issuer` (or `issuer`)
- `bakedBadgeImage` (or `bakedBadge`)

`ob2Assertion`, `ob2BadgeClass`, and `ob2Issuer` columns should contain JSON objects encoded as CSV string values.
