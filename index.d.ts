/// <reference types="node" />

import { Request } from 'express';

export interface Profile {
  id: string
  provider: string
  email?: string
  emailVerified?: boolean
  isPrivateEmail?: boolean
  name?: {
    firstName: string
    lastName: string
  }
}

export type VerifyNonceCallback = (
  req: IncomingMessage | Request,
  nonce: string,
  callback: (err: any, ok: boolean) => void
) => void;

export interface StateStore {
  store(req: IncomingMessage | Request, callback: (err: any, state?: string) => void): void;
  verify(
    req: IncomingMessage | Request,
    providedState: string,
    callback: (err: any, ok?: boolean, state?: string | { message: string }) => void
  ): void;
}

export interface Options {
  clientID: string;
  teamID: string;
  keyID: string;
  key?: string;
  keyFilePath?: string;
  authorizationURL?: string;
  tokenURL?: string;
  revokeURL?: string;
  jwksURL?: string;
  scope?: string[];
  sessionKey?: string;
  state?: boolean;
  store?: StateStore;
  passReqToCallback?: boolean;
  callbackURL?: string;
  clientSecretExpiry?: string;
  verifyNonce?: VerifyNonceCallback;
}

export interface AuthenticateOptions {
  callbackURL?: string;
  scope?: string[];
  state?: string;
  nonce?: string;
}

export interface AppleIdTokenClaims {
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  sub: string;
  nonce?: string;
  nonce_supported?: boolean;
  email?: string;
  email_verified?: boolean | 'true' | 'false';
  is_private_email?: boolean | 'true' | 'false';
  real_user_status?: number;
  [claim: string]: unknown;
}

export type ServerNotificationEventType =
  | 'email-enabled'
  | 'email-disabled'
  | 'consent-revoked'
  | 'account-deleted';

export interface ServerNotificationEvent {
  type: ServerNotificationEventType;
  sub: string;
  event_time: number;
  email?: string;
  is_private_email?: boolean | 'true' | 'false';
}

export interface ServerNotification {
  iss: string;
  aud: string;
  iat: number;
  jti?: string;
  events: ServerNotificationEvent;
  [claim: string]: unknown;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token: string;
}

export type VerifyCallback = (accessToken: string, refreshToken: string, profile: Profile, done: (error: any, user?: any) => void) => void;

import { Strategy as PassportStrategy } from 'passport-strategy';
import { IncomingMessage } from 'http';

declare class AppleStrategy extends PassportStrategy {
  constructor(options: Options, verify: VerifyCallback);

  authenticate(req: IncomingMessage | Request, options?: AuthenticateOptions): void;
  verifyNonce(req: IncomingMessage | Request, nonce_supported: boolean, nonce: string, callback: (err: any, ok: boolean) => void): void;
  parseErrorResponse(body: string): Error;

  /**
   * Verifies a Sign in with Apple identity token against Apple's public keys
   * and returns its claims. Useful when a native iOS/macOS app sends the
   * identity token directly to your backend.
   *
   * The audience and nonce must come from trusted server-side configuration
   * or session state — never from the incoming request itself.
   */
  verifyIdToken(idToken: string, options?: { audience?: string | string[]; nonce?: string }): Promise<AppleIdTokenClaims>;

  /**
   * Verifies a server-to-server notification JWS sent by Apple (the `payload`
   * field of the notification body) and returns its claims with the `events`
   * claim parsed. The application is responsible for acting on the event.
   */
  verifyServerNotification(signedPayload: string): Promise<ServerNotification>;

  /**
   * Exchanges a refresh token for a new access token, verifying that the
   * user's Apple session is still valid.
   */
  refreshAccessToken(refreshToken: string): Promise<TokenResponse>;

  /**
   * Revokes a refresh or access token, invalidating the associated user
   * session. Required for account deletion flows (App Store Review
   * Guideline 5.1.1(v)).
   */
  revokeToken(token: string, tokenTypeHint?: 'refresh_token' | 'access_token'): Promise<void>;
}

export default AppleStrategy;
export { AppleStrategy as Strategy };
