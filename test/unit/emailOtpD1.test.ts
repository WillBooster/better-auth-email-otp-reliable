import { betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';
import { drizzle } from 'drizzle-orm/d1';
import { Miniflare } from 'miniflare';
import { expect, test } from 'vitest';

import { reliableEmailOTP } from '../../src/index.js';
import { schema, schemaSql } from '../helpers/authDatabase.js';

test('D1 concurrent sends and rotations deliver a code that signs in', async () => {
  const worker = new Miniflare({ modules: true, script: 'export default {};', d1Databases: ['DB'] });
  try {
    const database = await worker.getD1Database('DB');
    await database.batch(
      schemaSql
        .split(';')
        .filter((sql) => sql.trim())
        .map((sql) => database.prepare(sql))
    );
    const sent: string[] = [];
    let nextOtp = 10_000_000;
    const auth = betterAuth({
      database: drizzleAdapter(drizzle(database), { provider: 'sqlite', schema }),
      baseURL: 'http://localhost:3000',
      secret: crypto.randomUUID(),
      advanced: { database: { generateId: 'serial' } },
      plugins: [
        reliableEmailOTP({
          otpLength: 8,
          expiresIn: 60,
          allowedAttempts: 5,
          resendStrategy: 'rotate',
          generateOTP: () => String(nextOtp++),
          storeOTP: { encrypt: async (value) => value, decrypt: async (value) => value },
          sendVerificationOTP: async ({ otp }) => {
            sent.push(otp);
          },
        }),
      ],
    });
    const email = 'd1@example.com';
    await Promise.all(
      Array.from({ length: 2 }, () => auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }))
    );
    expect(sent).toHaveLength(2);
    expect(sent[1]).toBe(sent[0]);
    const original = sent[0];
    sent.length = 0;
    await Promise.all(
      Array.from({ length: 2 }, () => auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } }))
    );
    expect(sent).toHaveLength(2);
    expect(sent[1]).toBe(sent[0]);
    expect(sent[0]).not.toBe(original);
    await expect(auth.api.signInEmailOTP({ body: { email, otp: sent[0]! } })).resolves.toMatchObject({
      user: { email },
    });
  } finally {
    await worker.dispose();
  }
}, 30_000);
