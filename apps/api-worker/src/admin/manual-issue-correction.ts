export interface ManualIssueCorrection {
  readonly issuanceRequestId: string;
  readonly recipientIdentity: string;
  readonly badgeTemplateId: string;
  readonly pathwayHandoffId?: string | undefined;
  readonly message: string;
}
