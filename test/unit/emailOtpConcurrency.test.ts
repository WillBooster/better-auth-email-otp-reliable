import { type BetterAuthOptions, betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { emailOTP } from 'better-auth/plugins';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { type EmailOtpPluginOptions, reliableEmailOTP } from '../../src/index.js';
import { schema, schemaSql } from '../helpers/authDatabase.js';

const SECRET = 'b'.repeat(32);
const sendVerificationOTP = vi.fn<(data: { email: string; otp: string }) => Promise<void>>();
const sqliteDatabase = new Database(':memory:');
const database = drizzle(sqliteDatabase);

sqliteDatabase.exec(schemaSql);

// oxlint-disable-next-line typescript/explicit-function-return-type -- keep the storage shape inferred by the plugin options.
const createStorage = () => ({
  encrypt: async (otp: string): Promise<string> => otp,
  decrypt: async (value: string): Promise<string> => value,
});

const createAuth = (
  options: Partial<EmailOtpPluginOptions> = {},
  databaseHooks?: BetterAuthOptions['databaseHooks'],
  useUpstream = false,
  beforeVerificationLookup?: () => Promise<void>
  // oxlint-disable-next-line typescript/explicit-function-return-type -- keep Better Auth's plugin endpoint inference in the test.
) =>
  betterAuth({
    databaseHooks,
    database: (authOptions: BetterAuthOptions) => {
      const adapter = drizzleAdapter(database, {
        provider: 'sqlite',
        schema,
      })(authOptions);
      return {
        ...adapter,
        async findMany<T>(args: Parameters<typeof adapter.findMany>[0]): Promise<T[]> {
          if (args.model === 'verification' && args.where?.some(({ field }) => field === 'identifier')) {
            await beforeVerificationLookup?.();
          }
          return adapter.findMany<T>(args);
        },
      };
    },
    baseURL: 'http://localhost:3000',
    secret: SECRET,
    advanced: { database: { generateId: 'serial' } },
    plugins: [
      (useUpstream ? emailOTP : reliableEmailOTP)({
        otpLength: 8,
        expiresIn: 60,
        allowedAttempts: 5,
        storeOTP: createStorage(),
        sendVerificationOTP,
        ...options,
      }),
    ],
  });

afterEach(() => {
  vi.useRealTimers();
  sendVerificationOTP.mockReset();
  sqliteDatabase.exec('DELETE FROM verification; DELETE FROM session; DELETE FROM account; DELETE FROM user;');
});

describe('reliableEmailOTP with a real SQLite adapter', () => {
  test('propagates a duplicate-key failure from a creation hook without rotating the emailed code', async () => {
    sendVerificationOTP.mockResolvedValue();
    const email = 'duplicate-hook@example.com';
    const auth = createAuth();
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    const failingAuth = createAuth(
      { resendStrategy: 'rotate' },
      {
        verification: {
          create: {
            before: async () => {
              sqliteDatabase.prepare('INSERT INTO verification SELECT * FROM verification').run();
            },
          },
        },
      }
    );
    await expect(failingAuth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } })).rejects.toMatchObject({
      code: 'SQLITE_CONSTRAINT_PRIMARYKEY',
    });
    expect(sendVerificationOTP.mock.calls).toHaveLength(1);
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });

  test('uses the default generator for upstream APIs when generateOTP is explicitly undefined', async () => {
    const auth = createAuth({ generateOTP: undefined });
    const email = 'default-generator@example.com';
    const otp = await auth.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    expect(otp).toMatch(/^\d{8}$/);
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });

  test('keeps the emailed code usable when a resend creation hook fails', async () => {
    sendVerificationOTP.mockResolvedValue();
    const email = 'before-hook@example.com';
    const auth = createAuth();
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    const failure = new Error('Creation denied');
    const failingAuth = createAuth(
      { resendStrategy: 'rotate' },
      {
        verification: {
          create: {
            before: async () => {
              throw failure;
            },
          },
        },
      }
    );
    await expect(failingAuth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } })).rejects.toBe(failure);
    expect(sendVerificationOTP.mock.calls).toHaveLength(1);
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });

  test.each([true, false])('reconciles a replacement gap (code existed initially: %s)', async (codeExisted) => {
    sendVerificationOTP.mockResolvedValue();
    const email = 'replacement-gap@example.com';
    if (codeExisted) await createAuth().api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const initialLookupComplete = Promise.withResolvers<void>();
    const startInsert = Promise.withResolvers<void>();
    const lookupPaused = Promise.withResolvers<void>();
    const resumeLookup = Promise.withResolvers<void>();
    const insertPaused = Promise.withResolvers<void>();
    const resumeInsert = Promise.withResolvers<void>();
    let lookups = 0;
    const authB = createAuth(
      { resendStrategy: 'rotate' },
      {
        verification: {
          create: {
            before: async () => {
              initialLookupComplete.resolve();
              await startInsert.promise;
            },
          },
        },
      },
      false,
      async () => {
        if (++lookups === 2) {
          lookupPaused.resolve();
          await resumeLookup.promise;
        }
      }
    );
    let inserts = 0;
    const authA = createAuth(
      { resendStrategy: 'rotate' },
      {
        verification: {
          create: {
            before: async () => {
              if (++inserts === 2) {
                insertPaused.resolve();
                await resumeInsert.promise;
              }
            },
          },
        },
      }
    );
    const sendingB = authB.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    await initialLookupComplete.promise;
    if (!codeExisted) await createAuth().api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    sendVerificationOTP.mockClear();
    startInsert.resolve();
    await lookupPaused.promise;
    const sendingA = authA.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    await insertPaused.promise;
    resumeLookup.resolve();
    try {
      await expect(sendingB).resolves.toEqual({ success: true });
    } finally {
      resumeInsert.resolve();
      await sendingA;
    }
    expect(sendVerificationOTP.mock.calls).toHaveLength(2);
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    expect(sendVerificationOTP.mock.calls[1]![0].otp).toBe(otp);
    await expect(authA.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });

  test('reuses a pending code issued by the upstream plugin before migration', async () => {
    sendVerificationOTP.mockResolvedValue();
    const email = 'migration@example.com';
    const legacy = createAuth({}, undefined, true);
    const otp = await legacy.api.createVerificationOTP({ body: { email, type: 'sign-in' } });
    const auth = createAuth();
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    expect(sendVerificationOTP.mock.calls[0]![0].otp).toBe(otp);
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });

  test('propagates verification creation hook failures without delivering a code', async () => {
    sendVerificationOTP.mockResolvedValue();
    const failure = new Error('Audit unavailable');
    const auth = createAuth(
      {},
      {
        verification: {
          create: {
            after: async () => {
              throw failure;
            },
          },
        },
      }
    );
    await expect(auth.api.sendVerificationOTP({ body: { email: 'hook@example.com', type: 'sign-in' } })).rejects.toBe(
      failure
    );
    expect(sendVerificationOTP).not.toHaveBeenCalled();
  });

  test.each([undefined, () => '12345678'])(
    'delivers one usable code for concurrent first requests (%s)',
    async (generateOTP) => {
      sendVerificationOTP.mockResolvedValue();
      const auth = createAuth({ generateOTP });
      const email = 'concurrent@example.com';

      await Promise.all([
        auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
        createAuth({ generateOTP }).api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
      ]);

      expect(sendVerificationOTP.mock.calls).toHaveLength(2);
      const firstOtp = sendVerificationOTP.mock.calls[0]?.[0].otp;
      const secondOtp = sendVerificationOTP.mock.calls[1]?.[0].otp;
      expect(firstOtp).toBeDefined();
      expect(secondOtp).toBe(firstOtp);
      await expect(auth.api.signInEmailOTP({ body: { email, otp: firstOtp! } })).resolves.toMatchObject({
        user: { email },
      });
    }
  );

  test.each(['expired', 'exhausted', 'rotate', 'undecryptable'] as const)(
    'delivers one usable code for concurrent replacement of an %s code',
    async (reason) => {
      sendVerificationOTP.mockResolvedValue();
      let encryptionKey = 'old-key';
      let nextOtp = 10_000_000;
      const auth = createAuth({
        generateOTP: () => String(nextOtp++),
        resendStrategy: reason === 'rotate' ? 'rotate' : 'reuse',
        allowedAttempts: 1,
        storeOTP: {
          encrypt: async (otp) => `${encryptionKey}:${otp}`,
          decrypt: async (value) => {
            if (!value.startsWith(`${encryptionKey}:`)) throw new Error('Old encryption key');
            return value.slice(encryptionKey.length + 1);
          },
        },
      });
      const email = 'replacement@example.com';

      await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
      const originalOtp = sendVerificationOTP.mock.calls[0]![0].otp;
      if (reason === 'expired') vi.setSystemTime(Date.now() + 61_000);
      if (reason === 'exhausted') {
        const wrongOtp = originalOtp === '00000000' ? '11111111' : '00000000';
        await expect(auth.api.signInEmailOTP({ body: { email, otp: wrongOtp } })).rejects.toMatchObject({
          body: { code: 'INVALID_OTP' },
        });
      }
      if (reason === 'undecryptable') encryptionKey = 'new-key';
      sendVerificationOTP.mockClear();

      await Promise.all([
        auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
        auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
      ]);

      expect(sendVerificationOTP.mock.calls).toHaveLength(2);
      const firstOtp = sendVerificationOTP.mock.calls[0]?.[0].otp;
      const secondOtp = sendVerificationOTP.mock.calls[1]?.[0].otp;
      expect(firstOtp).toBeDefined();
      expect(secondOtp).toBe(firstOtp);
      expect(firstOtp).not.toBe(originalOtp);
      await expect(auth.api.signInEmailOTP({ body: { email, otp: firstOtp! } })).resolves.toMatchObject({
        user: { email },
      });
    }
  );

  test('resending preserves failed attempts and a consumed code cannot sign in twice', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth({ allowedAttempts: 2 });
    const email = 'attempts@example.com';
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    const wrongOtp = otp === '00000000' ? '11111111' : '00000000';
    await expect(auth.api.signInEmailOTP({ body: { email, otp: wrongOtp } })).rejects.toMatchObject({
      body: { code: 'INVALID_OTP' },
    });
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    expect(sendVerificationOTP.mock.calls[1]![0].otp).toBe(otp);
    await expect(auth.api.signInEmailOTP({ body: { email, otp: wrongOtp } })).rejects.toMatchObject({
      body: { code: 'INVALID_OTP' },
    });
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).rejects.toMatchObject({
      body: { code: 'TOO_MANY_ATTEMPTS' },
    });
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const freshOtp = sendVerificationOTP.mock.calls[2]![0].otp;
    await expect(auth.api.signInEmailOTP({ body: { email, otp: freshOtp } })).resolves.toMatchObject({
      user: { email },
    });
    await expect(auth.api.signInEmailOTP({ body: { email, otp: freshOtp } })).rejects.toMatchObject({
      body: { code: 'INVALID_OTP' },
    });
  });

  test('extends a reused code beyond its original expiry', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth();
    const email = 'expiry@example.com';
    const start = Date.now();
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    vi.setSystemTime(start + 40_000);
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    expect(sendVerificationOTP.mock.calls[1]![0].otp).toBe(otp);
    vi.setSystemTime(start + 80_000);
    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({ user: { email } });
  });
});
