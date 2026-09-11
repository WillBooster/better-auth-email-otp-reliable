import { APIError, createAuthEndpoint, createAuthMiddleware, formCsrfMiddleware } from 'better-auth/api';
import { generateRandomString } from 'better-auth/crypto';
import type { EmailOTPOptions } from 'better-auth/plugins';
import { emailOTP } from 'better-auth/plugins';
import { z } from 'zod';

import { isUniqueConstraintError } from './databaseErrors.js';

type SendVerificationOtp = EmailOTPOptions['sendVerificationOTP'];
type OtpType = Parameters<SendVerificationOtp>[0]['type'];
type EndpointContext = NonNullable<Parameters<SendVerificationOtp>[1]>;

interface OtpStorage {
  encrypt: (otp: string) => Promise<string>;
  decrypt: (storedOtp: string) => Promise<string>;
}

/** Options for email OTP sign-in with automatic account creation. */
export interface EmailOtpPluginOptions extends Pick<
  EmailOTPOptions,
  'generateOTP' | 'rateLimit' | 'sendVerificationOTP' | 'resendStrategy'
> {
  otpLength: number;
  expiresIn: number;
  allowedAttempts: number;
  // Reusing a pending code (on resend and on a concurrent first request) needs a recoverable
  // code, so the storage must be able to decrypt what it stored.
  storeOTP: OtpStorage;
}

/** Raised when the verification email could not be handed to the mail provider. */
export const FAILED_TO_SEND_EMAIL = 'FAILED_TO_SEND_EMAIL';
const deliveryError = { code: FAILED_TO_SEND_EMAIL, message: 'Failed to send the verification email' } as const;

const STORAGE_PREFIX = 'reliable-email-otp:v1:';
const storedOtpSchema = z.tuple([z.string(), z.string()]);

const sendVerificationOtpBodySchema = z.object({
  email: z.string().meta({ description: 'Email address to send the OTP' }),
  type: z.literal('sign-in').meta({ description: 'Type of the OTP' }),
});

type BaseEmailOtpPlugin = ReturnType<typeof emailOTP>;
type SendVerificationOtpEndpoint = ReturnType<
  typeof createAuthEndpoint<
    '/email-otp/send-verification-otp',
    Omit<BaseEmailOtpPlugin['endpoints']['sendVerificationOTP']['options'], 'body'> & {
      body: typeof sendVerificationOtpBodySchema;
    },
    { success: boolean }
  >
>;

type EmailOtpPlugin = Omit<BaseEmailOtpPlugin, 'endpoints'> & {
  $ERROR_CODES: BaseEmailOtpPlugin['$ERROR_CODES'] & { FAILED_TO_SEND_EMAIL: typeof deliveryError };
  endpoints: Omit<BaseEmailOtpPlugin['endpoints'], 'sendVerificationOTP'> & {
    sendVerificationOTP: SendVerificationOtpEndpoint;
  };
  hooks: {
    before: {
      matcher: (ctx: { body?: unknown; path?: string }) => boolean;
      handler: ReturnType<typeof createAuthMiddleware>;
    }[];
  };
};

/** Email OTP sign-in with database-coordinated sends and awaited delivery. */
export function reliableEmailOTP(options: EmailOtpPluginOptions): EmailOtpPlugin {
  for (const value of [
    options.otpLength,
    options.expiresIn,
    options.allowedAttempts,
    ...(options.rateLimit ? [options.rateLimit.window, options.rateLimit.max] : []),
  ]) {
    z.number().int().positive().parse(value);
  }
  const { generateOTP, ...otherOptions } = options;
  const resolved = {
    ...otherOptions,
    ...(generateOTP ? { generateOTP } : {}),
    resendStrategy: options.resendStrategy ?? 'reuse',
    storeOTP: createOtpStorage(options.storeOTP),
    disableSignUp: false,
    overrideDefaultEmailVerification: false,
    sendVerificationOnSignUp: false,
    changeEmail: { enabled: false },
  };
  const base = emailOTP(resolved);
  return {
    ...base,
    $ERROR_CODES: { ...base.$ERROR_CODES, FAILED_TO_SEND_EMAIL: deliveryError },
    init(ctx: Parameters<NonNullable<typeof base.init>>[0]) {
      if (ctx.options.secondaryStorage) {
        throw new Error(
          'reliableEmailOTP does not support secondaryStorage; verification must use the database directly'
        );
      }
      return base.init?.(ctx);
    },
    endpoints: { ...base.endpoints, sendVerificationOTP: createSendVerificationOtpEndpoint(resolved) },
    hooks: { ...base.hooks, before: [createOtpShapeGuard(options.otpLength, !!options.generateOTP)] },
  };
}

function createOtpStorage(storage: OtpStorage): OtpStorage {
  return {
    async encrypt(otp) {
      // Distinguish this insertion from a competitor even when both generate a fixed code.
      return `${STORAGE_PREFIX}${JSON.stringify([crypto.randomUUID(), await storage.encrypt(otp)])}`;
    },
    async decrypt(value) {
      try {
        const ciphertext = value.startsWith(STORAGE_PREFIX)
          ? storedOtpSchema.parse(JSON.parse(value.slice(STORAGE_PREFIX.length)))[1]
          : value;
        return await storage.decrypt(ciphertext);
      } catch {
        // Pending codes from a previous encryption key must fail closed and be replaceable.
        return '';
      }
    },
  };
}

// Keep the upstream path so the client plugin and rate-limit rules continue to match.
function createSendVerificationOtpEndpoint(options: EmailOtpPluginOptions): SendVerificationOtpEndpoint {
  return createAuthEndpoint(
    '/email-otp/send-verification-otp',
    {
      method: 'POST',
      use: [formCsrfMiddleware],
      body: sendVerificationOtpBodySchema,
      metadata: {
        openapi: {
          operationId: 'sendEmailVerificationOTP',
          description: 'Send a verification OTP to an email',
          responses: {
            200: {
              description: 'Success',
              content: {
                'application/json': {
                  schema: { type: 'object', properties: { success: { type: 'boolean' } } },
                },
              },
            },
          },
        },
      },
    },
    async (ctx) => {
      const email = ctx.body.email.toLowerCase();
      if (!z.email().safeParse(email).success) {
        throw new APIError('BAD_REQUEST', { code: 'INVALID_EMAIL', message: 'Invalid email' });
      }
      const otp = await resolveOtp(ctx, options, email, ctx.body.type);

      // Awaited directly: upstream routes this through a helper that swallows the error and reports
      // success, leaving the user waiting for an email that never left. Every failure maps to the
      // same response so that nothing about the address leaks through the status.
      try {
        await options.sendVerificationOTP({ email, otp, type: ctx.body.type }, ctx);
      } catch (error) {
        ctx.context.logger.error('Failed to send the verification email', error);
        throw new APIError('SERVICE_UNAVAILABLE', deliveryError);
      }
      return ctx.json({ success: true });
    }
  );
}

/**
 * Resolves the code to send: the pending one when the resend strategy allows delivering it again,
 * otherwise a new one. When storing a new code loses to a concurrent request, that request's code
 * is delivered instead so that both emails carry a code that works.
 */
async function resolveOtp(
  ctx: EndpointContext,
  options: EmailOtpPluginOptions,
  email: string,
  type: OtpType
): Promise<string> {
  const identifier = toOtpIdentifier(type, email);

  let seen = await ctx.context.internalAdapter.findVerificationValue(identifier);
  if (seen && options.resendStrategy === 'reuse') {
    const reused = await reusePendingOtp(ctx, options, seen);
    if (reused) return reused;
  }

  const otp = options.generateOTP?.({ email, type }, ctx) || generateRandomString(options.otpLength, '0-9');
  const row = { identifier, value: `${await options.storeOTP.encrypt(otp)}:0`, expiresAt: expiresAt(options) };

  // A UNIQUE constraint on verification.identifier is the cross-process arbitration point.
  // Let Better Auth assign row IDs, including serial IDs used by existing applications.
  for (let pass = 0; ; pass++) {
    let created;
    try {
      created = await ctx.context.internalAdapter.createVerificationValue(row);
    } catch (error) {
      if (!isUniqueConstraintError(error)) throw error;
      const current = await ctx.context.internalAdapter.findVerificationValue(identifier);
      if (!current) {
        // The conflicting row can disappear before this request ever reads it.
        if (pass < 2) continue;
        throw error;
      }
      // A committed insertion followed by a failing create.after hook is not a conflict.
      if (current.value === row.value) throw error;
      if (options.resendStrategy === 'reuse' || current.id !== seen?.id || current.value !== seen?.value) {
        const concurrent = await reusePendingOtp(ctx, options, current);
        if (concurrent) return concurrent;
      }
      if (pass >= 2) {
        throw error;
      }
      seen = current;
      // Delete only the row observed by this request, because another request may have replaced it
      // after this lookup.
      await ctx.context.adapter.delete({
        model: 'verification',
        where: [
          { field: 'id', value: current.id },
          { field: 'value', value: current.value },
          { field: 'expiresAt', value: current.expiresAt },
        ],
      });
      continue;
    }
    if (!created) throw new Error('Verification creation was rejected');
    return otp;
  }
}

/** Returns the stored code with its lifetime extended, or `undefined` when it cannot be delivered again. */
async function reusePendingOtp(
  ctx: EndpointContext,
  options: EmailOtpPluginOptions,
  pending: { id: string; value: string; expiresAt: Date }
): Promise<string | undefined> {
  if (pending.expiresAt <= new Date()) return undefined;

  const separatorIndex = pending.value.lastIndexOf(':');
  const storedOtp = pending.value.slice(0, separatorIndex);
  const attempts = Number(pending.value.slice(separatorIndex + 1));
  if (separatorIndex < 1 || !Number.isInteger(attempts) || attempts < 0 || attempts >= options.allowedAttempts) {
    return undefined;
  }

  const otp = await options.storeOTP.decrypt(storedOtp);
  if (!otp) return undefined;

  const updated = await ctx.context.adapter.updateMany({
    model: 'verification',
    update: { expiresAt: expiresAt(options) },
    where: [
      { field: 'id', value: pending.id },
      { field: 'value', value: pending.value },
      { field: 'expiresAt', value: new Date(), operator: 'gt' },
    ],
  });
  if (!updated) return undefined;
  return otp;
}

function expiresAt(options: EmailOtpPluginOptions): Date {
  return new Date(Date.now() + options.expiresIn * 1000);
}

// The identifier format is internal to better-auth; it must match the one used by the untouched
// verification endpoints, which is why the tests sign in through them.
function toOtpIdentifier(type: OtpType, email: string): string {
  return `${type}-otp-${email}`;
}

// The email-OTP endpoints accept any string as the code, and an unusable stored code is decrypted
// as an empty string, which better-auth's constant-time comparison considers equal to an empty
// submission. The guard is limited to Better Auth's email OTP endpoints so that other OTP-based
// plugins can use their own code formats.
// oxlint-disable-next-line typescript/explicit-function-return-type -- typed by the plugin's inferred `hooks.before` element.
function createOtpShapeGuard(otpLength: number, allowAnyFormat: boolean) {
  const nonEmptyOtpBodySchema = z.object({ otp: z.string().min(1) });
  const otpBodySchema = z.object({ otp: z.string().length(otpLength).regex(/^\d+$/) });
  return {
    matcher: (ctx: { body?: unknown; path?: string }) =>
      !!(
        (ctx.path === '/sign-in/email-otp' || ctx.path?.startsWith('/email-otp/')) &&
        typeof ctx.body === 'object' &&
        ctx.body !== null &&
        'otp' in ctx.body
      ),
    handler: createAuthMiddleware(async (ctx) => {
      if (!nonEmptyOtpBodySchema.safeParse(ctx.body).success) {
        throw new APIError('BAD_REQUEST', { code: 'INVALID_OTP', message: 'Invalid OTP' });
      }
      if (allowAnyFormat) return;
      if (!otpBodySchema.safeParse(ctx.body).success) {
        throw new APIError('BAD_REQUEST', { code: 'INVALID_OTP', message: 'Invalid OTP' });
      }
    }),
  };
}
