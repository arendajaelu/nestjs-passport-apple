export interface Profile {
  id: string;
  provider: string;
  email?: string;
  emailVerified?: boolean;
  isPrivateEmail?: boolean;
  name?: {
    firstName: string;
    lastName: string;
  };
}

export type DoneCallback = (error: unknown, user?: unknown, info?: unknown) => void;

export type VerifyCallback = (
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: DoneCallback
) => void | Promise<void>;

export type VerifyCallbackWithRequest<TRequest = unknown> = (
  request: TRequest,
  accessToken: string,
  refreshToken: string,
  profile: Profile,
  done: DoneCallback
) => void | Promise<void>;

export type VerifyNonceCallback<TRequest = unknown> = (
  request: TRequest,
  nonce: string,
  callback: (err: unknown, ok: boolean) => void
) => void;

export interface StateStore<TRequest = unknown> {
  store(request: TRequest, callback: (err: unknown, state?: string) => void): void;
  verify(
    request: TRequest,
    providedState: string,
    callback: (err: unknown, ok?: boolean, state?: string | { message: string }) => void
  ): void;
}

export interface Options<TRequest = unknown> {
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
  store?: StateStore<TRequest>;
  passReqToCallback?: boolean;
  callbackURL?: string;
  clientSecretExpiry?: string;
  verifyNonce?: VerifyNonceCallback<TRequest>;
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

export interface VerifyIdTokenOptions {
  audience?: string | string[];
  nonce?: string;
}

/**
 * Passport strategy implementing Sign in with Apple.
 *
 * The request type is generic so the library does not depend on any specific
 * HTTP framework's type definitions. Consumers using `passReqToCallback` or a
 * custom state store can bind their own request type:
 *
 *     new Strategy<Request>({..., passReqToCallback: true}, (req, ...) => {...})
 */
declare class AppleStrategy<TRequest = unknown> {
  name: string;

  constructor(
    options: Options<TRequest> & { passReqToCallback: true },
    verify: VerifyCallbackWithRequest<TRequest>
  );
  constructor(options: Options<TRequest>, verify: VerifyCallback);

  authenticate(request: TRequest, options?: AuthenticateOptions): void;

  verifyNonce(
    request: TRequest,
    nonce_supported: boolean,
    nonce: string,
    callback: (err: unknown, ok: boolean) => void
  ): void;

  parseErrorResponse(body: string): Error | null;

  /**
   * Verifies a Sign in with Apple identity token against Apple's public keys
   * and returns its claims. Useful when a native iOS/macOS app sends the
   * identity token directly to your backend.
   *
   * The audience and nonce must come from trusted server-side configuration
   * or session state — never from the incoming request itself.
   */
  verifyIdToken(idToken: string, options?: VerifyIdTokenOptions): Promise<AppleIdTokenClaims>;

  /**
   * Validates a refresh token with Apple and obtains new tokens. An
   * `invalid_grant` rejection means the token is invalid, expired, consumed,
   * revoked, or does not match the configured client.
   */
  refreshAccessToken(refreshToken: string): Promise<TokenResponse>;

  /**
   * Revokes a refresh or access token, invalidating the associated Sign in
   * with Apple authorization. Required for account deletion flows (App Store
   * Review Guideline 5.1.1(v)). The application remains responsible for
   * clearing its own sessions and data.
   */
  revokeToken(token: string, tokenTypeHint?: 'refresh_token' | 'access_token'): Promise<void>;

  /**
   * Verifies a server-to-server notification JWS sent by Apple (the `payload`
   * field of the notification body) and returns its claims with the `events`
   * claim parsed. Deduplicate on `jti` at the application level to guard
   * against replayed deliveries.
   */
  verifyServerNotification(signedPayload: string): Promise<ServerNotification>;
}

export default AppleStrategy;
export { AppleStrategy as Strategy };
