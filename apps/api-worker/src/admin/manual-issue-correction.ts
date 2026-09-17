export interface ManualIssueCorrection {
  readonly recipientIdentity: string;
  readonly badgeTemplateId: string;
  readonly pathwayHandoffId?: string | undefined;
  readonly message: string;
}
