/// <reference types="node" />

import { Request } from 'express';

export interface Profile {
  id: string
  provider: string
  email: string
  emailVerified: boolean
  name?: {
    firstName: string
    lastName: string
  }
}

export interface Options {
  clientID: string;
  teamID: string;
  keyID: string;
  key?: string;
  keyFilePath?: string;
  authorizationURL?: string;
  tokenURL?: string;
  scope?: string[];
  sessionKey?: string;
  state?: boolean;
  passReqToCallback?: boolean;
  callbackURL?: string;
  clientSecretExpiry?: string;
  verifyNonce?: boolean;
}

export interface AuthenticateOptions {
  callbackURL?: string;
  scope?: string[];
  state?: string;
  nonce?: string;
}

export type VerifyCallback = (accessToken: string, refreshToken: string, profile: Profile, done: (error: any, user?: any) => void) => void;

import { Strategy as PassportStrategy } from 'passport-strategy';
import { IncomingMessage } from 'http';

declare class AppleStrategy extends PassportStrategy {
  constructor(options: Options, verify: VerifyCallback);

  authenticate(req: IncomingMessage | Request, options?: AuthenticateOptions): void;
  verifyNonce(req: IncomingMessage | Request, nonce_supported: boolean, nonce: string, callback: (err: any, ok: boolean) => void): void;
  parseErrorResponse(body: string): Error;
}

export default AppleStrategy;
export { AppleStrategy as Strategy };
