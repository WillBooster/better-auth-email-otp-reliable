# better-auth-email-otp-reliable

[![Test](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml/badge.svg)](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml)
[![wbfy](https://img.shields.io/badge/wbfy-20.12.0-1e90ff.svg)](https://github.com/WillBooster/shared/tree/main/packages/wbfy)

Reliable email OTP sign-in for [Better Auth](https://www.better-auth.com/), extracted
for Exercode and prompt-study. New addresses are registered automatically on
successful sign-in.

Concurrent send requests share a usable code. Resends reuse the pending code and
extend its expiry by default, without resetting failed attempts. Expired,
exhausted, or undecryptable codes are replaced. The sender is always awaited,
including when Better Auth has a background task handler: a rejected send returns
HTTP 503 with error code `FAILED_TO_SEND_EMAIL`. A retry can reuse that pending code.

## Usage

Install this package alongside Better Auth and Zod. Replace the server's `emailOTP`
plugin with `reliableEmailOTP`; keep `emailOTPClient` on the client.

```ts
import { betterAuth } from 'better-auth';
import { symmetricDecrypt, symmetricEncrypt } from 'better-auth/crypto';
import { reliableEmailOTP } from 'better-auth-email-otp-reliable';

export const auth = betterAuth({
  database, // Your Better Auth database adapter.
  secret,
  plugins: [
    reliableEmailOTP({
      otpLength: 8,
      expiresIn: 300,
      allowedAttempts: 5,
      storeOTP: {
        encrypt: (otp) => symmetricEncrypt({ key: secret, data: otp }),
        decrypt: (value) => symmetricDecrypt({ key: secret, data: value }),
      },
      sendVerificationOTP: async ({ email, otp }) => {
        await sendMail({ to: email, subject: 'Your sign-in code', text: otp });
      },
    }),
  ],
});
```

`database`, `secret`, and `sendMail` above are supplied by the application. The
sender must return the delivery promise and reject on failure. Custom storage
must encrypt codes in a recoverable format; decryption failures are treated as
unusable codes. Stored ciphertext is wrapped with a per-insertion random identifier
so creation-hook failures can be distinguished from competing inserts, even with
fixed codes. Existing unwrapped ciphertext remains readable. Empty submissions are
rejected before verification. Supply
`generateOTP` to use a custom nonempty code format, including fixed codes in local
tests. Numeric options must be positive integers.

`resendStrategy: 'rotate'` explicitly replaces a code on a new send request;
concurrent insert conflicts still share the winning code. Prefer the default
`'reuse'` so delayed emails stay useful.

## Database contract

The `verification.identifier` column **must have a database UNIQUE constraint**.
The existing Exercode and prompt-study schemas already provide it. Better Auth's
standard schema alone does not. For a new integration, deduplicate any existing
rows and add a unique index using your normal migration workflow before enabling
the plugin. Serial and string primary keys are supported; row IDs must not be
reused after deletion. Better Auth's memory adapter is suitable only for basic
development flows because it does not enforce uniqueness.

Creation goes through Better Auth's internal adapter. Conflicting requests read
the winning row and reuse its code; replacement deletes only the observed row,
matching its ID, value, and expiry. This coordinates independent application
instances through the database without a process-local lock.

Only recognized duplicate-key errors enter conflict recovery; other database and
creation-hook errors propagate without deleting a pending code. Duplicate errors
are recognized by SQLite/libSQL extended codes, PostgreSQL SQLSTATE `23505`, MySQL
`ER_DUP_ENTRY`/1062, or MongoDB 11000, including nested `cause` chains. Adapters with
other error formats fail closed and need compatibility work before use.

Secondary storage is rejected at initialization, even with
`verification.storeInDatabase: true`: conditional database writes cannot safely
keep Better Auth's verification cache in sync. Use a database-only Better Auth
instance for this plugin.

Conditional expiry updates and replacement deletes bypass verification update
and delete hooks. Creation invokes verification create hooks; hooks must preserve
the identifier, value, and expiry. Hook-dependent integrations require further
work tracked in [issue #6](https://github.com/WillBooster/better-auth-email-otp-reliable/issues/6).

## Scope and compatibility

The overridden send endpoint accepts only `type: 'sign-in'` and sends to existing
and new addresses alike. Signup email verification, email changes, and disabling
automatic signup are not configurable through this plugin. Other Better Auth
endpoints retain upstream behavior; the delivery and resend guarantees apply to
`/email-otp/send-verification-otp`. Verification and sign-in retain upstream
single-use and attempt-limit handling. Simultaneous verification and sending are
not serialized by this package, and provider acceptance does not guarantee inbox
delivery.

The package depends on Better Auth's internal verification format and adapter
behavior. Compatibility is tested with Better Auth 1.6.29; review these contracts
before adopting another minor release. Tests exercise actual HTTP sign-in,
delivery failure recovery, and real SQLite concurrency with the applications'
serial-ID and unique-identifier schema. Run `bun run verify-full` and `bun run build`
when changing the package.
