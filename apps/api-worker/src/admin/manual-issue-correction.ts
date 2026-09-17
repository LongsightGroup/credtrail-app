export interface ManualIssueCorrection {
  readonly issuanceRequestId: string;
  readonly recipientIdentity: string;
  readonly badgeTemplateId: string;
  readonly pathwayHandoffId?: string | undefined;
  readonly message: string;
  readonly previousAward?: {
    readonly assertionId: string;
    readonly issuedAt: string;
    readonly confirmationKey: string;
  };
}
