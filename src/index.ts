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
const storedOtpSchema = z.tuple([z.uuid(), z.string()]);

const sendVerificationOtpBodySchema = z.object({
  email: z.string().meta({ description: 'Email address to send the OTP' }),
  type: z.literal('sign-in').meta({ description: 'Type of the OTP' }),
});

type BaseEmailOtpPlugin = ReturnType<typeof emailOTP>;
type PluginContext = Parameters<NonNullable<BaseEmailOtpPlugin['init']>>[0];
type CreationFailures = WeakMap<object, string>;
type SendVerificationOtpEndpoint = ReturnType<
  typeof createAuthEndpoint<
    '/email-otp/send-verification-otp',
    Omit<BaseEmailOtpPlugin['endpoints']['sendVerificationOTP']['options'], 'body'> & {
      body: typeof sendVerificationOtpBodySchema;
    },
    { success: boolean }
  >
>;

type EmailOtpPlugin = Omit<BaseEmailOtpPlugin, 'endpoints' | 'init'> & {
  init: (ctx: PluginContext) => { context: Pick<PluginContext, 'adapter'> };
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
  const { generateOTP, resendStrategy, ...otherOptions } = options;
  const creationFailures: CreationFailures = new WeakMap();
  const sharedOptions = {
    ...otherOptions,
    ...(generateOTP ? { generateOTP } : {}),
    ...(resendStrategy ? { resendStrategy } : {}),
    storeOTP: createOtpStorage(options.storeOTP),
    disableSignUp: false,
    overrideDefaultEmailVerification: false,
    sendVerificationOnSignUp: false,
    changeEmail: { enabled: false },
  };
  const base = emailOTP(sharedOptions);
  return {
    ...base,
    $ERROR_CODES: { ...base.$ERROR_CODES, FAILED_TO_SEND_EMAIL: deliveryError },
    init(ctx: PluginContext) {
      assertDatabaseStorage(ctx.options);
      return { context: { adapter: trackCreationFailures(ctx.adapter, creationFailures) } };
    },
    endpoints: {
      ...base.endpoints,
      sendVerificationOTP: createSendVerificationOtpEndpoint(
        { ...sharedOptions, resendStrategy: resendStrategy ?? 'reuse' },
        creationFailures
      ),
    },
    hooks: {
      ...base.hooks,
      before: [createDatabaseStorageGuard(), createOtpShapeGuard(options.otpLength, !!options.generateOTP)],
    },
  };
}

function createDatabaseStorageGuard(): EmailOtpPlugin['hooks']['before'][number] {
  return {
    matcher: () => true,
    handler: createAuthMiddleware(async (ctx) => {
      // Other plugins can add options after this plugin's init has run.
      assertDatabaseStorage(ctx.context.options);
    }),
  };
}

function assertDatabaseStorage(options: PluginContext['options']): void {
  if (options.secondaryStorage) {
    throw new Error('reliableEmailOTP does not support secondaryStorage; verification must use the database directly');
  }
}

function trackCreationFailures(
  adapter: PluginContext['adapter'],
  failures: CreationFailures
): PluginContext['adapter'] {
  const create: PluginContext['adapter']['create'] = async (args) => {
    try {
      return await adapter.create(args);
    } catch (error) {
      // Hook errors may carry the same driver code; record only actual verification insert failures.
      if (args.model === 'verification' && typeof error === 'object' && error !== null) {
        const value = z.string().safeParse(args.data.value);
        if (value.success) failures.set(error, value.data);
      }
      throw error;
    }
  };
  const boundMethods = new WeakMap<object, unknown>();
  // A separate target also permits intercepting a frozen adapter's create method.
  return new Proxy(Object.create(adapter) as PluginContext['adapter'], {
    get(_target, key) {
      if (key === 'create') return create;
      const value: unknown = Reflect.get(adapter, key, adapter);
      if (typeof value !== 'function') return value;
      if (!boundMethods.has(value)) boundMethods.set(value, value.bind(adapter));
      return boundMethods.get(value);
    },
    getPrototypeOf: () => Reflect.getPrototypeOf(adapter),
    ownKeys: () => Reflect.ownKeys(adapter),
    getOwnPropertyDescriptor(_target, key) {
      const descriptor = Reflect.getOwnPropertyDescriptor(adapter, key);
      return descriptor ? { ...descriptor, configurable: true } : undefined;
    },
  });
}

function createOtpStorage(storage: OtpStorage): OtpStorage {
  return {
    async encrypt(otp) {
      // Distinguish this insertion from a competitor even when both generate a fixed code.
      return `${STORAGE_PREFIX}${JSON.stringify([crypto.randomUUID(), await storage.encrypt(otp)])}`;
    },
    async decrypt(value) {
      try {
        return await storage.decrypt(unwrapStoredOtp(value));
      } catch {
        // Pending codes from a previous encryption key must fail closed and be replaceable.
        return '';
      }
    },
  };
}

function unwrapStoredOtp(value: string): string {
  if (!value.startsWith(STORAGE_PREFIX)) return value;
  try {
    return storedOtpSchema.parse(JSON.parse(value.slice(STORAGE_PREFIX.length)))[1];
  } catch {
    // A prefix alone does not distinguish legacy ciphertext from a versioned envelope.
    return value;
  }
}

// Keep the upstream path so the client plugin and rate-limit rules continue to match.
function createSendVerificationOtpEndpoint(
  options: EmailOtpPluginOptions,
  creationFailures: CreationFailures
): SendVerificationOtpEndpoint {
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
      const otp = await resolveOtp(ctx, options, email, ctx.body.type, creationFailures);

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
  type: OtpType,
  creationFailures: CreationFailures
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
      if (
        typeof error !== 'object' ||
        error === null ||
        creationFailures.get(error) !== row.value ||
        !isUniqueConstraintError(error)
      )
        throw error;
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

  const where = [
    { field: 'id', value: pending.id },
    { field: 'value', value: pending.value },
  ];
  const updated = await ctx.context.adapter.updateMany({
    model: 'verification',
    update: { expiresAt: expiresAt(options) },
    where: [...where, { field: 'expiresAt', value: new Date(), operator: 'gt' }],
  });
  if (!updated) {
    // Some drivers count changed rows, so an unchanged expiry can also report zero.
    const current = await ctx.context.adapter.findOne({
      model: 'verification',
      where: [...where, { field: 'expiresAt', value: new Date(), operator: 'gt' }],
    });
    if (!current) return undefined;
  }
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
