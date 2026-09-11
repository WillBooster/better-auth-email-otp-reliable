import { z } from 'zod';

const databaseErrorSchema = z.object({
  code: z.union([z.string(), z.number()]).optional(),
  errno: z.number().optional(),
  rawCode: z.number().optional(),
  cause: z.unknown().optional(),
});
const uniqueConstraintCodes = new Set<string | number>([
  'SQLITE_CONSTRAINT_UNIQUE',
  'SQLITE_CONSTRAINT_PRIMARYKEY',
  '23505',
  'ER_DUP_ENTRY',
  11_000,
  2067,
  1555,
]);

/** Recognizes duplicate-key failures, including driver errors wrapped by an ORM. */
export function isUniqueConstraintError(error: unknown): boolean {
  const seen = new Set<unknown>();
  while (!seen.has(error)) {
    seen.add(error);
    const result = databaseErrorSchema.safeParse(error);
    if (!result.success) return false;
    const { code, errno, rawCode, cause } = result.data;
    if (
      (code !== undefined && uniqueConstraintCodes.has(code)) ||
      errno === 1062 ||
      rawCode === 2067 ||
      rawCode === 1555
    ) {
      return true;
    }
    error = cause;
  }
  return false;
}
