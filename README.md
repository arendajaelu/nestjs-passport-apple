# NestJS Passport Apple Strategy

This strategy seamlessly integrates Apple login capabilities into NestJS applications by leveraging Passport and its authentication framework.

## Features

- Supports NestJS v10 and v11
- Utilizes Apple's OAuth2.0 for user authentication
- Uses NestJS's AuthGuard for easy integration
- Provides strongly-typed Profile object

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
      callbackURL: process.env.APPLE_OAUTH_CALLBACK_URL
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
- `scope`: (Optional) An array of scopes, e.g., `['email', 'name']`
- `sessionKey`: (Optional) Session Key
- `state`: (Optional) Should state parameter be used
- `passReqToCallback`: (Optional) Should request be passed to the `validate` callback; default is `false`
- `callbackURL`: (Optional) Callback URL

### Validate Callback

The `validate` callback is called after successful authentication and contains the `accessToken`, `refreshToken`, and `profile`.

## Tutorial: Apple Login with NestJS 

For a detailed tutorial on implementing Apple Login with NestJS, refer to the following article:  

[**How to Implement Apple Login with NestJS in Seconds**](https://blog.devgenius.io/how-to-implement-apple-login-with-nestjs-in-seconds-b88f05abe847)  

## License

Licensed under [MIT](./LICENSE).
