# NestJS Passport Apple Strategy — Sign in with Apple for NestJS

[![npm version](https://img.shields.io/npm/v/@arendajaelu/nestjs-passport-apple.svg)](https://www.npmjs.com/package/@arendajaelu/nestjs-passport-apple)
[![npm downloads](https://img.shields.io/npm/dt/@arendajaelu/nestjs-passport-apple.svg)](https://www.npmjs.com/package/@arendajaelu/nestjs-passport-apple)
[![license](https://img.shields.io/npm/l/@arendajaelu/nestjs-passport-apple.svg)](./LICENSE)
[![node](https://img.shields.io/node/v/@arendajaelu/nestjs-passport-apple.svg)](https://nodejs.org)
[![CI](https://github.com/arendajaelu/nestjs-passport-apple/actions/workflows/ci.yml/badge.svg)](https://github.com/arendajaelu/nestjs-passport-apple/actions/workflows/ci.yml)

**Apple login for NestJS in minutes.** A Passport strategy that integrates **Sign in with Apple** into NestJS applications — Apple OAuth 2.0 authentication, identity token (JWT) verification, refresh token validation, token revocation for account deletion, and Apple's server-to-server notifications, all in one typed, tested package with **900k+ downloads**.

Works with `@nestjs/passport` and `AuthGuard`, supports web apps (Services ID) and native iOS/macOS apps (App ID), and verifies every token against Apple's public keys before your code ever sees it.

## Features

- 🍎 **Plug-and-play Apple login** — works with NestJS 10 & 11 via `AuthGuard`
- 🔐 **Verified before you see it** — ID tokens are checked against Apple's public keys; your `validate` only receives trusted data
- 🧾 **Typed `Profile`** — email, verification status, and Hide My Email flag included
- 📱 **Native app support** — verify identity tokens from iOS/macOS apps, with nonce protection (`verifyIdToken`)
- ♻️ **Session validation** — check that a user's Apple authorization is still alive (`refreshAccessToken`)
- 🗑️ **Account deletion ready** — revoke tokens per App Store Guideline 5.1.1(v) (`revokeToken`)
- 📨 **Server-to-server notifications** — verify Apple's signed account events (`verifyServerNotification`)
- 🛡️ **CSRF protection** — optional OAuth `state` generation and validation
- ✅ **Fully tested** — unit and integration suites run the complete flow against a mock Apple server, and published types are compiled by a real strict-mode NestJS consumer in CI

## Requirements

- Node.js 18 or later when used with NestJS 10
- Node.js 20 or later when used with NestJS 11 (NestJS 11 itself requires Node.js 20)

## Installation

```bash
npm install @arendajaelu/nestjs-passport-apple
```

## Usage

### Strategy Setup

The following example shows all commonly used options:

```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from '@arendajaelu/nestjs-passport-apple';

const APPLE_STRATEGY_NAME = 'apple';

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, APPLE_STRATEGY_NAME) {
  constructor() {
    super({
      clientID: process.env.APPLE_OAUTH_CLIENT_ID,
      teamID: process.env.APPLE_TEAMID,
      keyID: process.env.APPLE_KEYID,
      key: process.env.APPLE_KEY_CONTENTS,
      // OR
      keyFilePath: process.env.APPLE_KEYFILE_PATH,
      callbackURL: process.env.APPLE_OAUTH_CALLBACK_URL,
      scope: ['email', 'name'],
      // state: true, // recommended in production for CSRF protection; requires express-session
      passReqToCallback: false,
    });
  }

  async validate(_accessToken: string, _refreshToken: string, profile: Profile) {
    return {
      emailAddress: profile.email,
      firstName: profile.name?.firstName || '',
      lastName: profile.name?.lastName || '',
    };
  }
}

@Injectable()
export class AppleOAuthGuard extends AuthGuard(APPLE_STRATEGY_NAME) {}
```

> **Note**: Register `AppleStrategy` in the `providers` array of your module.

### Controller Endpoints

```typescript
import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { ApiTags } from '@nestjs/swagger';
import { AppleOAuthGuard } from './strategies/apple.strategy';

@ApiTags('oauth')
@Controller('oauth')
export class OAuthController {
  @Get('apple')
  @UseGuards(AppleOAuthGuard)
  async appleLogin() {}

  @Post('apple/callback')
  @UseGuards(AppleOAuthGuard)
  async appleCallback(@Req() req) {
    return req.user;
  }
}
```

> Apple delivers the authorization callback as an `application/x-www-form-urlencoded` HTTP POST whenever scopes such as `name` or `email` are requested (the strategy always sends `response_mode=form_post`). The callback route must therefore be a `@Post` handler with URL-encoded body parsing enabled — NestJS enables this by default. The callback URL must exactly match an HTTPS return URL registered in the Apple Developer portal; Apple does not accept `localhost` or IP-address callback URLs. Authorization codes are single-use and expire after five minutes.

### Strategy Options

| Option | Required | Description |
|---|---|---|
| `clientID` | Yes | Apple Services ID (or App ID) used as the OAuth client identifier |
| `teamID` | Yes | Apple Developer Team ID |
| `keyID` | Yes | Identifier of the Sign in with Apple private key |
| `key` | Yes* | Contents of the private key. Provide either `key` or `keyFilePath` |
| `keyFilePath` | Yes* | Path to the private key file; loaded with `fs.readFileSync` |
| `callbackURL` | No | OAuth redirect URI; must match a return URL registered with Apple |
| `scope` | No | Array of scopes, e.g. `['email', 'name']` |
| `state` | No | Enables OAuth `state` generation and validation to protect against CSRF: a random value is stored in the session before redirecting to Apple and compared with the value Apple posts back. Strongly recommended in production. Requires `express-session` or compatible session middleware. Defaults to `false` |
| `store` | No | Custom state store implementing `store(req, callback)` and `verify(req, state, callback)`, for deployments without session middleware |
| `sessionKey` | No | Session key under which state is stored; defaults to `apple:<hostname>` |
| `passReqToCallback` | No | Passes the request as the first argument of `validate`; defaults to `false` |
| `clientSecretExpiry` | No | Lifetime of the generated client secret JWT; defaults to `'5 minutes'`. Secrets are cached and regenerated automatically before expiry |
| `authorizationURL` | No | Defaults to `https://appleid.apple.com/auth/authorize` |
| `tokenURL` | No | Defaults to `https://appleid.apple.com/auth/token` |
| `revokeURL` | No | Defaults to `https://appleid.apple.com/auth/revoke` |
| `jwksURL` | No | JWKS endpoint used to fetch Apple's public keys; defaults to `https://appleid.apple.com/auth/keys` |

### Validate Callback

After successful authentication, `validate` receives the `accessToken`, `refreshToken`, and verified `profile`. The value it returns becomes `req.user`. Store the `refreshToken` if you intend to validate sessions or revoke access later.

### Profile Object

```typescript
{
  id: string;               // stable Apple user identifier (the `sub` claim)
  provider: 'apple';
  email?: string;
  emailVerified?: boolean;
  isPrivateEmail?: boolean; // true when the address is a Hide My Email relay
  name?: {                  // present only on the user's first authorization
    firstName: string;
    lastName: string;
  };
}
```

> **Important**: Always associate application accounts with `profile.id`, not the email address. Apple posts the `user` object (containing `name`) only during the user's **first** authorization — persist it at that point. Because the name originates from the browser form post rather than from the signed identity token, validate and sanitize it before storing or displaying it. Subsequent authorizations do not include the `user` object; the identity token normally carries the email claim, but applications should tolerate a missing email as well (some managed Apple Accounts have none).

### Private Relay Email Addresses

Do not identify or filter Apple relay addresses by inspecting the email domain; rely on the verified `isPrivateEmail` flag instead. If your email validation or delivery infrastructure filters by domain, it must accept all of Apple's relay domains: `private.icloud.com` (used for addresses generated from mid-2026 onward) as well as the legacy `privaterelay.appleid.com` and `icloud.com`.

## Beyond Login

The strategy instance exposes the remaining Sign in with Apple lifecycle operations. Because the strategy is a NestJS provider, it can be injected wherever these operations are needed.

### Verifying a Native App's Identity Token

When your backend also serves an iOS/macOS application using `ASAuthorizationAppleIDCredential`, the app submits an identity token directly. Verify it against Apple's public keys:

```typescript
const claims = await appleStrategy.verifyIdToken(identityToken, {
  audience: 'com.example.bundleid', // the app's bundle ID, from server-side configuration
  nonce: expectedNonce,             // the nonce your server issued for this sign-in attempt
});
// claims.sub is the stable Apple user identifier
```

- `audience` defaults to the configured `clientID`; override it when the token was issued for a different client, such as the app's bundle ID.
- When a `nonce` is supplied, verification fails unless the token's nonce claim matches exactly. Apple requires nonce validation whenever a nonce is used, as protection against replay attacks.

> **Security**: The expected `audience` and `nonce` must come from trusted server-side configuration or server-side session state. Never accept either value from the untrusted request being authenticated.

### Validating a Refresh Token and Obtaining New Tokens

```typescript
const tokens = await appleStrategy.refreshAccessToken(refreshToken);
// tokens: { access_token, token_type, expires_in, id_token }
```

Apple recommends validating a stored refresh token no more than once per day; more frequent validation risks throttling. An `invalid_grant` error means the authorization code or refresh token is invalid, expired, already consumed, revoked, or does not match the configured client — in all cases, the application should require the user to authenticate again.

### Revoking Tokens (Account Deletion)

App Store Review Guideline 5.1.1(v) requires applications that offer account creation to also offer account deletion, including revocation of Sign in with Apple tokens:

```typescript
await appleStrategy.revokeToken(refreshToken); // token_type_hint defaults to 'refresh_token'
// or
await appleStrategy.revokeToken(accessToken, 'access_token');
```

A successful call revokes the token and its associated Sign in with Apple authorization, or confirms that the token was already invalid — Apple returns HTTP 200 in both cases.

> **Note**: Revoking the Apple token does not delete the application account or terminate the application's own sessions. After revocation, the application remains responsible for deleting applicable user data, removing stored tokens, clearing local sessions and cookies, and returning the client to an unauthenticated state.

### Processing Server-to-Server Notifications

Apple can notify your server when users change their relationship with your application. Register a notification endpoint URL in the Apple Developer portal; Apple then delivers signed events as an HTTP POST with a JSON body of the form `{ "payload": "<signed JWS>" }`. Verify the signature before acting on any event:

```typescript
@Post('apple/notifications')
async appleNotifications(@Body() body: { payload: string }) {
  const notification = await this.appleStrategy.verifyServerNotification(body.payload);

  switch (notification.events.type) {
    case 'email-enabled':   // user enabled email forwarding
    case 'email-disabled':  // user disabled email forwarding
      break;
    case 'consent-revoked': // user revoked authorization — end their sessions
      break;
    case 'account-deleted': // user deleted their Apple Account — remove associated data
      break;
  }
}
```

`verifyServerNotification` validates the JWS signature against Apple's public keys, along with the issuer and audience, and returns the claims with the `events` payload parsed. The library performs verification only; deciding how to act on each event remains the application's responsibility. Verification failures throw — treat such requests as forged and reject them.

> **Replay protection**: a verified notification carries a `jti` (unique notification ID). Because a captured delivery could be replayed to your endpoint while still within its validity window, persist processed `jti` values (database, Redis, etc.) and reject duplicates before acting on an event:
>
> ```typescript
> const accepted = await this.notificationStore.claim(notification.jti);
> if (!accepted) {
>   throw new ConflictException('Notification already processed');
> }
> ```

### TypeScript: Request Typing

The strategy's type declarations are fully self-contained — no `@types/express` or `@types/passport-strategy` required. The request type is generic, so `passReqToCallback` and custom state stores work with any HTTP framework's request type:

```typescript
import type { Request } from 'express'; // or FastifyRequest from 'fastify'

export class AppleStrategy extends PassportStrategy(Strategy<Request>, 'apple') {
  constructor() {
    super({ /* options */, passReqToCallback: true });
  }

  validate(req: Request, accessToken: string, refreshToken: string, profile: Profile) {
    return { id: profile.id };
  }
}
```

## Testing

The repository ships with a comprehensive automated test suite built on the Node.js native test runner — no additional test dependencies are required:

```bash
npm test
```

The suite covers two levels:

- **Unit tests** (`test/strategy.test.js`): constructor validation, authorization redirect parameters, Apple error handling, profile claim parsing (including the string and boolean forms of `email_verified` and `is_private_email`), revocation and refresh request formats, client secret generation, expiry-driven regeneration, per-client secret caching, and state store behavior (session-based validation, mismatch rejection, and custom stores).
- **Integration tests** (`test/integration.test.js`): the complete authentication flow executed against a local mock of Apple's token and JWKS endpoints with genuine RS256-signed identity tokens, along with negative cases — wrong audience, unknown signing key, expired tokens, nonce mismatches, and forged server notifications.

## Tutorials

For a complete, up-to-date walkthrough covering authentication, token revocation, and the full Sign in with Apple lifecycle:

[**Apple Login with NestJS in 2026–2027: A Complete Guide to Authentication, Token Revocation and More**](https://medium.com/@joosepwong/apple-login-with-nestjs-in-2026-2027-a-complete-guide-to-authentication-token-revocation-and-9ec3f08863e5)

The original walkthrough of the Apple Developer portal setup is also available:

[**How to Implement Apple Login with NestJS in Seconds**](https://blog.devgenius.io/how-to-implement-apple-login-with-nestjs-in-seconds-b88f05abe847)

## FAQ

### How do I implement Apple login in NestJS?

Install this package, register the strategy shown in [Strategy Setup](#strategy-setup) as a NestJS provider, and guard your routes with `AuthGuard('apple')`. The [complete guide](https://medium.com/@joosepwong/apple-login-with-nestjs-in-2026-2027-a-complete-guide-to-authentication-token-revocation-and-9ec3f08863e5) walks through every step, including the Apple Developer portal configuration.

### How do I verify an Apple identity token from an iOS app on my NestJS backend?

Use [`verifyIdToken`](#verifying-a-native-apps-identity-token) with your app's bundle ID as the audience. It validates the RS256 signature against Apple's JWKS, plus issuer, expiry, and (optionally) nonce.

### How do I revoke Sign in with Apple tokens for account deletion?

Call [`revokeToken`](#revoking-tokens-account-deletion) with the user's stored refresh token. This satisfies App Store Review Guideline 5.1.1(v), which requires apps offering account creation to also revoke Apple tokens on account deletion.

### Why is the user's name missing after the first Apple login?

Apple sends the `name` (and the `user` object) only on the user's **first** authorization. Persist it on first login — see [Profile Object](#profile-object).

### Does this work with the new `private.icloud.com` Hide My Email addresses?

Yes. The strategy exposes a verified `isPrivateEmail` flag, so you never need to match relay domains yourself — see [Private Relay Email Addresses](#private-relay-email-addresses).

### Can my server get notified when a user revokes access or deletes their Apple Account?

Yes — register a notification endpoint with Apple and verify each event with [`verifyServerNotification`](#processing-server-to-server-notifications).

## License

Licensed under [MIT](./LICENSE).

---

*Keywords: Sign in with Apple, Apple login NestJS, NestJS Apple OAuth, passport-apple, Apple OAuth2 strategy, apple-signin, Apple ID authentication, verify Apple identity token, Apple token revocation, Apple server-to-server notifications, Hide My Email, NestJS authentication, Passport.js Apple strategy*
