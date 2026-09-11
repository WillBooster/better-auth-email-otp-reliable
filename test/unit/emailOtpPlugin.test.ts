import { betterAuth } from 'better-auth';
import { memoryAdapter } from 'better-auth/adapters/memory';
import { APIError } from 'better-auth/api';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { afterEach, describe, expect, test, vi } from 'vitest';

import { FAILED_TO_SEND_EMAIL, reliableEmailOTP } from '../../src/index.js';

const SECRET = 'a'.repeat(32);
const OTP_LENGTH = 8;
const sendVerificationOTP = vi.fn<(data: { email: string; otp: string }) => Promise<void>>();

const createStorage = (): {
  encrypt: (otp: string) => Promise<string>;
  decrypt: (value: string) => Promise<string>;
} => ({
  encrypt: (otp: string) => symmetricEncrypt({ key: SECRET, data: otp }),
  decrypt: async (value: string) => {
    try {
      return await symmetricDecrypt({ key: SECRET, data: value });
    } catch {
      return '';
    }
  },
});

// oxlint-disable-next-line typescript/explicit-function-return-type -- keep Better Auth's plugin endpoint inference in the test.
const createAuth = (storage = createStorage(), generateOTP?: () => string) =>
  betterAuth({
    database: memoryAdapter({ user: [], account: [], session: [], verification: [] }),
    baseURL: 'http://localhost:3000',
    secret: SECRET,
    plugins: [
      reliableEmailOTP({
        otpLength: OTP_LENGTH,
        expiresIn: 60,
        allowedAttempts: 5,
        storeOTP: storage,
        resendStrategy: 'reuse',
        ...(generateOTP ? { generateOTP } : {}),
        sendVerificationOTP,
      }),
    ],
  });

afterEach(() => sendVerificationOTP.mockReset());

describe('reliableEmailOTP', () => {
  test('signs in with the emailed code', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth();
    const email = 'user@example.com';

    await expect(auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } })).resolves.toEqual({
      success: true,
    });
    const otp = sendVerificationOTP.mock.calls[0]?.[0].otp;
    if (!otp) throw new Error('The email sender was not called');
    expect(otp).toMatch(new RegExp(`^\\d{${OTP_LENGTH}}$`));

    await expect(auth.api.signInEmailOTP({ body: { email, otp } })).resolves.toMatchObject({
      user: { email },
    });
  });

  test('reports a failed send to the caller', async () => {
    sendVerificationOTP.mockRejectedValueOnce(new Error('SMTP unavailable')).mockResolvedValue();
    const auth = createAuth();

    const error = await auth.api
      .sendVerificationOTP({ body: { email: 'user@example.com', type: 'sign-in' } })
      .catch((error: unknown) => error);
    expect(error).toBeInstanceOf(APIError);
    expect(error).toMatchObject({ status: 'SERVICE_UNAVAILABLE', body: { code: FAILED_TO_SEND_EMAIL } });
    await auth.api.sendVerificationOTP({ body: { email: 'user@example.com', type: 'sign-in' } });
    const otp = sendVerificationOTP.mock.calls[1]![0].otp;
    expect(otp).toBe(sendVerificationOTP.mock.calls[0]![0].otp);
    await expect(auth.api.signInEmailOTP({ body: { email: 'user@example.com', otp } })).resolves.toMatchObject({
      user: { email: 'user@example.com' },
    });
  });

  test('reuses a pending code when a user resends it', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth();
    const email = 'user@example.com';

    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });

    expect(sendVerificationOTP.mock.calls).toHaveLength(2);
    expect(sendVerificationOTP.mock.calls[1]?.[0].otp).toBe(sendVerificationOTP.mock.calls[0]?.[0].otp);
  });

  test('rejects an empty code when custom storage cannot decrypt it', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth(
      {
        encrypt: async (otp: string): Promise<string> => otp,
        decrypt: async (): Promise<string> => '',
      },
      () => 'CUSTOM'
    );
    const email = 'undecryptable@example.com';
    await auth.api.sendVerificationOTP({ body: { email, type: 'sign-in' } });

    const error = await auth.api.signInEmailOTP({ body: { email, otp: '' } }).catch((error: unknown) => error);
    expect(error).toMatchObject({ status: 'BAD_REQUEST', body: { code: 'INVALID_OTP' } });
  });

  test('accepts a custom code format through the HTTP handler', async () => {
    sendVerificationOTP.mockResolvedValue();
    const auth = createAuth(createStorage(), () => 'CUSTOM-CODE');
    const email = 'Custom@Example.com';
    const send = await auth.handler(
      new Request('http://localhost:3000/api/auth/email-otp/send-verification-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, type: 'sign-in' }),
      })
    );
    expect(send.status).toBe(200);
    const otp = sendVerificationOTP.mock.calls[0]![0].otp;
    const signIn = await auth.handler(
      new Request('http://localhost:3000/api/auth/sign-in/email-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, otp }),
      })
    );
    expect(signIn.status).toBe(200);
    expect(await signIn.json()).toMatchObject({ user: { email: email.toLowerCase() } });
    expect(signIn.headers.get('set-cookie')).toContain('better-auth.session_token=');
  });
});
