export const REPORTING_HIGHLIGHT_ROW_LIMIT = 5;

export interface ReportingHighlightRow {
  groupId: string;
  issuedCount: number;
}

export const selectReportingHighlightRows = <RowType extends ReportingHighlightRow>(
  rows: readonly RowType[],
): RowType[] => {
  return [...rows]
    .sort((left, right) => {
      if (right.issuedCount !== left.issuedCount) {
        return right.issuedCount - left.issuedCount;
      }

      return left.groupId.localeCompare(right.groupId);
    })
    .slice(0, REPORTING_HIGHLIGHT_ROW_LIMIT);
};
