# better-auth-email-otp-reliable

[![npm version](https://img.shields.io/npm/v/better-auth-email-otp-reliable.svg)](https://www.npmjs.com/package/better-auth-email-otp-reliable)
[![license](https://img.shields.io/npm/l/better-auth-email-otp-reliable.svg)](https://www.npmjs.com/package/better-auth-email-otp-reliable)
[![Test](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml/badge.svg)](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![wbfy](https://img.shields.io/badge/wbfy-20.17.0-1e90ff.svg)](https://github.com/WillBooster/shared/tree/main/packages/wbfy)

Reliable email OTP sign-in for [Better Auth](https://www.better-auth.com/), extracted
for Exercode and prompt-study. New addresses are registered automatically on
successful sign-in.

Concurrent send requests share a usable code. Sign-in resends reuse the pending code and
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
fixed codes. Legacy ciphertext is passed unchanged to the decryptor unless it
matches the complete envelope: `reliable-email-otp:v1:` followed by a JSON
`[UUID, ciphertext]` tuple. Legacy formats already producing that complete envelope
need explicit migration; a matching prefix alone remains readable. Empty submissions are
rejected before verification. Supply
`generateOTP` to use a custom nonempty code format, including fixed codes in local
tests. Numeric options must be positive integers.

`resendStrategy: 'rotate'` explicitly replaces a code on a new send request;
concurrent insert conflicts still share the winning code. Prefer the default
`'reuse'` so delayed emails stay useful.

The reuse default applies to the overridden sign-in sender. Retained upstream
endpoints use their upstream defaults unless `resendStrategy` is explicitly supplied.

Once a replacement is stored, a later creation-hook or delivery failure does not
restore the old code: a concurrent sender may already have delivered the replacement.
The request still reports the error, and a retry can issue or deliver a usable code.

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

The adapter records verification insertion failures without changing the thrown
errors. Only recognized duplicate-key errors from that insertion enter conflict
recovery; other database and creation-hook errors propagate instead of triggering
conflict recovery. Duplicate errors
are recognized by SQLite/libSQL extended codes, Cloudflare D1's uniqueness error
message, PostgreSQL SQLSTATE `23505`, MySQL `ER_DUP_ENTRY`/1062, or MongoDB 11000,
including nested `cause` chains. Adapters with
other error formats fail closed and need compatibility work before use.

Secondary storage supplied directly is rejected at initialization. The finalized
configuration is also checked before API requests to catch storage added by other
plugins. This includes `verification.storeInDatabase: true`: conditional database writes cannot safely
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
behavior. Compatibility is tested with Better Auth 1.6.29 (prompt-study) and 1.7.2
(Exercode); the peer range excludes 1.8 and later until those contracts are reviewed.
The development dependency follows Exercode's 1.7.2. CI checks that locked version,
then installs 1.6.29 in its disposable checkout and repeats type checking, tests,
and the build. Tests exercise actual HTTP sign-in,
delivery failure recovery, and real SQLite concurrency with the applications'
serial-ID and unique-identifier schema, plus D1 concurrency through Miniflare's
actual Workers runtime. Run `bun run verify-full` and `bun run build`
when changing the package.
