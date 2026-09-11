# better-auth-email-otp-reliable

Reliable email OTP delivery for [Better Auth](https://www.better-auth.com/).

This package keeps a pending OTP usable when concurrent send requests collide,
reuses a pending OTP for resends, and propagates synchronous delivery failures
to the caller.
