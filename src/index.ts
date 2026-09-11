import { APIError, createAuthEndpoint, createAuthMiddleware, formCsrfMiddleware } from 'better-auth/api';
import { generateRandomString } from 'better-auth/crypto';
import type { EmailOTPOptions } from 'better-auth/plugins';
import { emailOTP } from 'better-auth/plugins';
import { z } from 'zod';

type SendVerificationOtp = EmailOTPOptions['sendVerificationOTP'];
type OtpType = Parameters<SendVerificationOtp>[0]['type'];
type EndpointContext = NonNullable<Parameters<SendVerificationOtp>[1]>;

interface OtpStorage {
  encrypt: (otp: string) => Promise<string>;
  decrypt: (storedOtp: string) => Promise<string>;
}

// `disableSignUp` is excluded: the send endpoint below sends a code to every address alike, and
// the option would only make the upstream `/sign-in/email-otp` reject an unknown address's code
// instead of creating its account, which is how this app signs users up.
export interface EmailOtpPluginOptions extends Omit<EmailOTPOptions, 'storeOTP' | 'disableSignUp'> {
  otpLength: number;
  expiresIn: number;
  allowedAttempts: number;
  // Reusing a pending code (on resend and on a concurrent first request) needs a recoverable
  // code, so the storage must be able to decrypt what it stored.
  storeOTP: OtpStorage;
}

/** Raised when the verification email could not be handed to the mail provider. */
export const FAILED_TO_SEND_EMAIL = 'FAILED_TO_SEND_EMAIL';

const OTP_TYPES = ['email-verification', 'sign-in', 'forget-password', 'change-email'] as const satisfies OtpType[];

const sendVerificationOtpBodySchema = z.object({
  email: z.string().meta({ description: 'Email address to send the OTP' }),
  type: z.enum(OTP_TYPES).meta({ description: 'Type of the OTP' }),
});

/**
 * better-auth's `emailOTP` plugin whose send endpoint is replaced to fix two upstream defects:
 * - two concurrent first requests for the same address each emailed a code, and the second
 *   request silently invalidated the first code (better-auth/better-auth#11181);
 * - a failed `sendVerificationOTP` for a sign-in code was reported to the client as
 *   `success: true` (better-auth/better-auth#11107).
 * The override can be removed once better-auth ships better-auth/better-auth#11182 and #11183.
 * Only that endpoint is replaced: the plugin's `overrideDefaultEmailVerification` and
 * `sendVerificationOnSignUp` flows still call the upstream implementation, so they must stay off.
 */
// oxlint-disable-next-line typescript/explicit-function-return-type -- the plugin type must stay inferred so that better-auth infers its endpoints.
export function reliableEmailOTP(options: EmailOtpPluginOptions) {
  const base = emailOTP(options);
  return {
    ...base,
    endpoints: { ...base.endpoints, sendVerificationOTP: createSendVerificationOtpEndpoint(options) },
    hooks: { ...base.hooks, before: [createOtpShapeGuard(options.otpLength)] },
  };
}

// Mirrors the upstream `/email-otp/send-verification-otp` endpoint (path, body and OpenAPI
// metadata, so that the client plugin and the rate-limit rules keep matching it), differing in how
// the code is issued (`resolveOtp`) and in awaiting the send so that its failure can reach the client.
// oxlint-disable-next-line typescript/explicit-function-return-type -- the endpoint type must stay inferred.
function createSendVerificationOtpEndpoint(options: EmailOtpPluginOptions) {
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
      // This app sends codes for signing in only. Upstream looks the account up first and answers
      // success for an unknown address, which would turn a rejection here into an account-existence
      // probe, so the type is settled before anything that depends on the address.
      if (ctx.body.type !== 'sign-in') {
        throw new APIError('BAD_REQUEST', { message: 'Invalid OTP type' });
      }

      const otp = await resolveOtp(ctx, options, email, ctx.body.type);

      // Awaited directly: upstream routes this through a helper that swallows the error and reports
      // success, leaving the user waiting for an email that never left. Every failure maps to the
      // same response so that nothing about the address leaks through the status.
      try {
        await options.sendVerificationOTP({ email, otp, type: ctx.body.type }, ctx);
      } catch (error) {
        ctx.context.logger.error('Failed to send the verification email', error);
        throw new APIError('SERVICE_UNAVAILABLE', {
          code: FAILED_TO_SEND_EMAIL,
          message: 'Failed to send the verification email',
        });
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
    const reused = await reusePendingOtp(ctx, options, identifier, seen);
    if (reused) return reused;
  }

  const otp = options.generateOTP?.({ email, type }, ctx) || generateRandomString(options.otpLength, '0-9');
  const row = { identifier, value: `${await options.storeOTP.encrypt(otp)}:0`, expiresAt: expiresAt(options) };

  // The unique identifier is the only reason an insert can fail. A row that was not there at the
  // last lookup, or that has changed since, belongs to a concurrent request that is about to email
  // its own code: deliver that same code instead of replacing it, because replacing would silently
  // invalidate the code the user is about to receive. Only the row read at the last lookup is
  // replaced (with `reuse` it could not be reused, with `rotate` the user asked for a new code),
  // and only while it is still that row, so that a replacement never removes what a concurrent
  // request stored in the meantime. The insert after a replacement can lose to a concurrent request
  // in the same way, hence the loop; each pass hands over to a code another request just stored,
  // so a few passes cover any interleaving.
  for (let pass = 0; ; pass++) {
    try {
      await ctx.context.internalAdapter.createVerificationValue(row);
      return otp;
    } catch (error) {
      // Rows are told apart by id: the value changes whenever a failed attempt is counted.
      const current = await ctx.context.internalAdapter.findVerificationValue(identifier);
      if (current && current.id !== seen?.id) {
        const concurrent = await reusePendingOtp(ctx, options, identifier, current);
        if (concurrent) return concurrent;
      }
      if (pass >= 2) throw error;
      seen = current;
      if (current) {
        // Scoped to the row that was read by its id: the internal adapter deletes by identifier
        // alone, which would also remove a row a concurrent request stored since the lookup. Going
        // through the adapter skips the database hooks, of which this app configures none for
        // verification rows.
        await ctx.context.adapter.delete({ model: 'verification', where: [{ field: 'id', value: current.id }] });
      }
    }
  }
}

/** Returns the stored code with its lifetime extended, or `undefined` when it cannot be delivered again. */
async function reusePendingOtp(
  ctx: EndpointContext,
  options: EmailOtpPluginOptions,
  identifier: string,
  pending: { value: string; expiresAt: Date }
): Promise<string | undefined> {
  if (pending.expiresAt < new Date()) return undefined;

  const separatorIndex = pending.value.lastIndexOf(':');
  const storedOtp = pending.value.slice(0, separatorIndex);
  const attempts = Number(pending.value.slice(separatorIndex + 1));
  if (attempts >= options.allowedAttempts) return undefined;

  const otp = await options.storeOTP.decrypt(storedOtp);
  if (!otp) return undefined;

  await ctx.context.internalAdapter.updateVerificationByIdentifier(identifier, { expiresAt: expiresAt(options) });
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
// submission. Any request carrying a code must carry one of the shape this app issues; matching on
// the field rather than on a list of paths keeps every verifying endpoint covered, including ones
// the app does not use itself.
// oxlint-disable-next-line typescript/explicit-function-return-type -- typed by the plugin's inferred `hooks.before` element.
function createOtpShapeGuard(otpLength: number) {
  const otpBodySchema = z.object({ otp: z.string().length(otpLength).regex(/^\d+$/) });
  return {
    matcher: (ctx: { body?: unknown }) => typeof ctx.body === 'object' && ctx.body !== null && 'otp' in ctx.body,
    handler: createAuthMiddleware(async (ctx) => {
      if (!otpBodySchema.safeParse(ctx.body).success) {
        throw new APIError('BAD_REQUEST', { code: 'INVALID_OTP', message: 'Invalid OTP' });
      }
    }),
  };
}
