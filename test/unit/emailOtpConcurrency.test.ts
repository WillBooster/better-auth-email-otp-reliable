import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { reliableEmailOTP } from '../../src/index.js';

const SECRET = 'b'.repeat(32);
const sendVerificationOTP = vi.fn<(data: { email: string; otp: string }) => Promise<void>>();
const sqliteDatabase = new Database(':memory:');
const database = drizzle(sqliteDatabase);

const user = sqliteTable('user', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  email: text('email').notNull(),
  emailVerified: integer('email_verified', { mode: 'boolean' }).notNull(),
  image: text('image'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

const account = sqliteTable('account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull(),
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
  id: text('id').primaryKey(),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  token: text('token').notNull(),
  userId: text('user_id').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

const verification = sqliteTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp_ms' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
});

sqliteDatabase.exec(`
  CREATE TABLE user (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL,
    image TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE account (
    id TEXT PRIMARY KEY NOT NULL,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
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
    id TEXT PRIMARY KEY NOT NULL,
    expires_at INTEGER NOT NULL,
    token TEXT NOT NULL,
    user_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE verification (
    id TEXT PRIMARY KEY NOT NULL,
    identifier TEXT NOT NULL,
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
const createAuth = () =>
  betterAuth({
    database: drizzleAdapter(database, { provider: 'sqlite', schema: { user, account, session, verification } }),
    baseURL: 'http://localhost:3000',
    secret: SECRET,
    plugins: [
      reliableEmailOTP({
        otpLength: 8,
        expiresIn: 60,
        allowedAttempts: 5,
        storeOTP: createStorage(),
        resendStrategy: 'reuse',
        sendVerificationOTP,
      }),
    ],
  });

afterEach(() => {
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
      auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }),
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
});
