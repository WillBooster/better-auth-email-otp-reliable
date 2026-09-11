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
const createAuth = () =>
  betterAuth({
    database: memoryAdapter({ user: [], account: [], session: [], verification: [] }),
    baseURL: 'http://localhost:3000',
    secret: SECRET,
    plugins: [
      reliableEmailOTP({
        otpLength: OTP_LENGTH,
        expiresIn: 60,
        allowedAttempts: 5,
        storeOTP: createStorage(),
        resendStrategy: 'reuse',
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
    sendVerificationOTP.mockRejectedValue(new Error('SMTP unavailable'));
    const auth = createAuth();

    const error = await auth.api
      .sendVerificationOTP({ body: { email: 'user@example.com', type: 'sign-in' } })
      .catch((error: unknown) => error);
    expect(error).toBeInstanceOf(APIError);
    expect(error).toMatchObject({ status: 'SERVICE_UNAVAILABLE', body: { code: FAILED_TO_SEND_EMAIL } });
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
});
