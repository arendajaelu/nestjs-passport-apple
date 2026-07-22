# NestJS Passport Apple Strategy

This strategy seamlessly integrates Apple login capabilities into NestJS applications by leveraging Passport and its authentication framework.

## Features

- Supports NestJS v10 and v11
- Utilizes Apple's OAuth2.0 for user authentication
- Uses NestJS's AuthGuard for easy integration
- Provides strongly-typed Profile object, including Apple's `is_private_email` (Hide My Email) flag
- Verifies identity tokens sent directly from native iOS/macOS apps (`verifyIdToken`)
- Refreshes access tokens to check that the user's Apple session is still valid (`refreshAccessToken`)
- Revokes tokens for account deletion flows as required by App Store Review Guideline 5.1.1(v) (`revokeToken`)

## Requirements

- Node.js 18 or later

## Installation

```bash
npm install @arendajaelu/nestjs-passport-apple
```

## Usage

### Strategy Setup

Here's a full example detailing all available options:

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

> **Note**: Make sure to add `AppleStrategy` to the `providers` array in your module.

### Using Guard in Controller

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

### Strategy Options

- `clientID`: Apple OAuth2.0 Client ID
- `teamID`: Apple Developer Team ID
- `keyID`: Apple Key ID
- `key`: Contents of the Apple Key. If you want the library to load the contents, use `keyFilePath` instead.
- `keyFilePath`: File path to Apple Key; library will load content using `fs.readFileSync`
- `authorizationURL`: (Optional) Authorization URL; default is `https://appleid.apple.com/auth/authorize`
- `tokenURL`: (Optional) Token URL; default is `https://appleid.apple.com/auth/token`
- `revokeURL`: (Optional) Token revocation URL; default is `https://appleid.apple.com/auth/revoke`
- `jwksURL`: (Optional) JWKS URL used to fetch Apple's public keys for ID token verification; default is `https://appleid.apple.com/auth/keys`
- `scope`: (Optional) An array of scopes, e.g., `['email', 'name']`
- `sessionKey`: (Optional) Session Key
- `state`: (Optional) Should state parameter be used
- `passReqToCallback`: (Optional) Should request be passed to the `validate` callback; default is `false`
- `callbackURL`: (Optional) Callback URL
- `clientSecretExpiry`: (Optional) Expiry of the generated client secret JWT, e.g. `'5 minutes'`; default is `'5 minutes'`

### Validate Callback

The `validate` callback is called after successful authentication and contains the `accessToken`, `refreshToken`, and `profile`.

### Profile Object

```typescript
{
  id: string;               // Apple user identifier (the `sub` claim)
  provider: 'apple';
  email?: string;
  emailVerified?: boolean;
  isPrivateEmail?: boolean; // true when the user chose Hide My Email
  name?: {                  // only present on the user's FIRST authorization — persist it!
    firstName: string;
    lastName: string;
  };
}
```

> **Note**: Apple only sends `name` (and posts the `user` object) on the very first authorization. Store it on first login; subsequent logins only include the email claims.

## Beyond Login

The strategy instance also exposes methods for the rest of the Sign in with Apple lifecycle. Since the strategy is a NestJS provider, you can inject it wherever you need these.

### Verifying a native app's identity token

If your backend also serves an iOS/macOS app using `ASAuthorizationAppleIDCredential`, the app sends you an identity token directly. Verify it against Apple's public keys:

```typescript
const claims = await appleStrategy.verifyIdToken(identityToken);
// claims.sub is the stable Apple user ID; claims.email may be present
```

Pass `{ audience: 'your.bundle.id' }` as a second argument if the token was issued for a different client ID (e.g. your app's bundle ID instead of your Services ID).

### Checking that the user's Apple session is still valid

```typescript
const tokens = await appleStrategy.refreshAccessToken(refreshToken);
// tokens: { access_token, token_type, expires_in, id_token }
```

Apple recommends verifying a user's refresh token at most once a day. A rejected `invalid_grant` means the user has revoked access for your app or signed out.

### Revoking tokens (account deletion)

App Store Review Guideline 5.1.1(v) requires apps offering account creation to also offer account deletion, including revoking Sign in with Apple tokens:

```typescript
await appleStrategy.revokeToken(refreshToken); // defaults to token_type_hint=refresh_token
// or
await appleStrategy.revokeToken(accessToken, 'access_token');
```

A successful call invalidates the user's session with your app.

## Tutorial: Apple Login with NestJS 

For a detailed tutorial on implementing Apple Login with NestJS, refer to the following article:  

[**How to Implement Apple Login with NestJS in Seconds**](https://blog.devgenius.io/how-to-implement-apple-login-with-nestjs-in-seconds-b88f05abe847)  

## License

Licensed under [MIT](./LICENSE).
