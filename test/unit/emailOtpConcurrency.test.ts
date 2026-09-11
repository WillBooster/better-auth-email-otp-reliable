import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { type EmailOtpPluginOptions, reliableEmailOTP } from '../../src/index.js';

const SECRET = 'b'.repeat(32);
const sendVerificationOTP = vi.fn<(data: { email: string; otp: string }) => Promise<void>>();
const sqliteDatabase = new Database(':memory:');
const database = drizzle(sqliteDatabase);

const user = sqliteTable('user', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  email: text('email').notNull(),
  emailVerified: integer('email_verified', { mode: 'boolean' }).notNull(),
  image: text('image'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

const account = sqliteTable('account', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: integer('user_id').notNull(),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: integer('access_token_expires_at', { mode: 'timestamp_ms' }),
  refreshTokenExpiresAt: integer('refresh_token_expires_at', { mode: 'timestamp_ms' }),
  scope: text('scope'),
  password: text('password'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

const session = sqliteTable('session', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  token: text('token').notNull(),
  userId: integer('user_id').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

const verification = sqliteTable('verification', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  identifier: text('identifier').notNull().unique(),
  value: text('value').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

sqliteDatabase.exec(`
  CREATE TABLE user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL,
    image TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at INTEGER,
    refresh_token_expires_at INTEGER,
    scope TEXT,
    password TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE session (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    expires_at INTEGER NOT NULL,
    token TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,
    value TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
`);

// oxlint-disable-next-line typescript/explicit-function-return-type -- keep the storage shape inferred by the plugin options.
const createStorage = () => ({
  encrypt: async (otp: string): Promise<string> => otp,
  decrypt: async (value: string): Promise<string> => value,
});

// oxlint-disable-next-line typescript/explicit-function-return-type -- keep Better Auth's plugin endpoint inference in the test.
const createAuth = (options: Partial<EmailOtpPluginOptions> = {}) =>
  betterAuth({
    database: drizzleAdapter(database, { provider: 'sqlite', schema: { user, account, session, verification } }),
    baseURL: 'http://localhost:3000',
    secret: SECRET,
    advanced: { database: { generateId: 'serial' } },
    plugins: [
      reliableEmailOTP({
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
  test('delivers one usable code for concurrent first requests', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth();
    const email = 'concurrent@example.com';

    await Promise.all([
      auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
      createAuth().api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
    ]);

    expect(sendVerificationOTP.mock.calls).toHaveLength(2);
    const firstOtp = sendVerificationOTP.mock.calls[0]?.[0].otp;
    const secondOtp = sendVerificationOTP.mock.calls[1]?.[0].otp;
    expect(firstOtp).toBeDefined();
    expect(secondOtp).toBe(firstOtp);
    await expect(auth.api.signInEmailOTP({ body: { email, otp: firstOtp! } })).resolves.toMatchObject({
      user: { email },
    });
  });

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
