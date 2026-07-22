import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import {
  Profile,
  ServerNotification,
  Strategy,
  TokenResponse,
} from '@arendajaelu/nestjs-passport-apple';

@Injectable()
export class AppleStrategy extends PassportStrategy(Strategy, 'apple') {
  constructor() {
    super({
      clientID: 'client-id',
      teamID: 'team-id',
      keyID: 'key-id',
      keyFilePath: './AuthKey.p8',
      callbackURL: 'https://example.com/oauth/apple/callback',
      scope: ['email', 'name'],
    });
  }

  validate(accessToken: string, refreshToken: string, profile: Profile) {
    const email: string | undefined = profile.email;
    const isPrivate: boolean | undefined = profile.isPrivateEmail;
    return { accessToken, refreshToken, id: profile.id, email, isPrivate };
  }
}

interface AppRequest {
  session?: Record<string, unknown>;
}

@Injectable()
export class AppleStrategyWithRequest extends PassportStrategy(
  Strategy<AppRequest>,
  'apple-with-request',
) {
  constructor() {
    super({
      clientID: 'client-id',
      teamID: 'team-id',
      keyID: 'key-id',
      key: 'key-contents',
      passReqToCallback: true,
    });
  }

  validate(
    request: AppRequest,
    accessToken: string,
    _refreshToken: string,
    profile: Profile,
  ) {
    void request.session;
    return { id: profile.id, accessToken };
  }
}

export async function lifecycle(strategy: Strategy): Promise<void> {
  const claims = await strategy.verifyIdToken('token', {
    audience: 'com.example.app',
    nonce: 'expected-nonce',
  });
  const sub: string = claims.sub;
  void sub;

  const tokens: TokenResponse = await strategy.refreshAccessToken('refresh-token');
  void tokens.access_token;

  await strategy.revokeToken('refresh-token');
  await strategy.revokeToken('access-token', 'access_token');

  const notification: ServerNotification = await strategy.verifyServerNotification('jws');
  switch (notification.events.type) {
    case 'email-enabled':
    case 'email-disabled':
    case 'consent-revoked':
    case 'account-deleted':
      break;
  }
}
