export const isUniqueConstraintError = (error: unknown): error is Error => {
  return (
    error instanceof Error &&
    (error.message.includes("UNIQUE constraint failed") ||
      error.message.includes("duplicate key value violates unique constraint"))
  );
};
