# better-auth-email-otp-reliable

[![Test](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml/badge.svg)](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml)
[![wbfy](https://img.shields.io/badge/wbfy-20.12.0-1e90ff.svg)](https://github.com/WillBooster/shared/tree/main/packages/wbfy)

Reliable email OTP delivery for [Better Auth](https://www.better-auth.com/).

This package keeps a pending OTP usable when concurrent send requests collide,
reuses a pending OTP for resends, and propagates synchronous delivery failures
to the caller.

When Better Auth secondary storage is configured, set `verification.storeInDatabase`
to `true`. The concurrent-send guarantee requires the database-backed atomic
reservation path.

The atomic reservation and row replacement paths do not invoke Better Auth's
verification database hooks. Applications that depend on those hooks should
track [issue #6](https://github.com/WillBooster/better-auth-email-otp-reliable/issues/6).
