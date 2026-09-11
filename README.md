# better-auth-email-otp-reliable

[![Test](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml/badge.svg)](https://github.com/WillBooster/better-auth-email-otp-reliable/actions/workflows/test.yml)
[![wbfy](https://img.shields.io/badge/wbfy-20.12.0-1e90ff.svg)](https://github.com/WillBooster/shared/tree/main/packages/wbfy)

Reliable email OTP delivery for [Better Auth](https://www.better-auth.com/).

This package keeps a pending OTP usable when concurrent send requests collide,
reuses a pending OTP for resends, and propagates synchronous delivery failures
to the caller.
