import type { BadgeTemplateRecord } from "@credtrail/db";
import type { UpdateBadgeTemplateRequest } from "@credtrail/validation";

export interface BadgeTemplateFieldChange {
  field: string;
  from: string | null;
  to: string | null;
}

const fieldReaders: ReadonlyArray<{
  requestKey: keyof UpdateBadgeTemplateRequest;
  field: string;
  read: (template: BadgeTemplateRecord) => string | null;
}> = [
  { requestKey: "slug", field: "slug", read: (template) => template.slug },
  { requestKey: "title", field: "title", read: (template) => template.title },
  {
    requestKey: "description",
    field: "description",
    read: (template) => template.description,
  },
  {
    requestKey: "criteriaUri",
    field: "criteriaUri",
    read: (template) => template.criteriaUri,
  },
  {
    requestKey: "trustedCredentialMetadata",
    field: "trustedCredentialMetadata",
    read: (template) => template.trustedCredentialMetadataJson ?? null,
  },
];

export const buildBadgeTemplateFieldChanges = (
  existing: BadgeTemplateRecord,
  updated: BadgeTemplateRecord,
  request: UpdateBadgeTemplateRequest,
): BadgeTemplateFieldChange[] => {
  const changes: BadgeTemplateFieldChange[] = [];

  for (const fieldReader of fieldReaders) {
    if (request[fieldReader.requestKey] === undefined) {
      continue;
    }

    const from = fieldReader.read(existing);
    const to = fieldReader.read(updated);

    if (from !== to) {
      changes.push({
        field: fieldReader.field,
        from,
        to,
      });
    }
  }

  return changes;
};

export const buildBadgeTemplateImageUriChange = (
  from: string | null,
  to: string | null,
): BadgeTemplateFieldChange | null => {
  if (from === to) {
    return null;
  }

  return {
    field: "imageUri",
    from,
    to,
  };
};
