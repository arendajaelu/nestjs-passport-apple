const fs = require('fs');

const passport = require('passport-strategy');
const OAuth2 = require('oauth').OAuth2;
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const NullStateStore = require('./state/null');
const SessionStateStore = require('./state/session');
const AuthorizationError = require('./errors/authorizationerror');
const TokenError = require('./errors/tokenerror');
const InternalOAuthError = require('./errors/internaloautherror');

const jwks_client = jwksClient({
    strictSsl: true,
    rateLimit: true,
    cache: true,
    cacheMaxEntries: 100,
    cacheMaxAge: 1000 * 60 * 60 * 24,
    jwksUri: 'https://appleid.apple.com/auth/keys'
});

const getAppleJWKSKey = (header, callback) => {
    jwks_client
        .getSigningKey(header.kid)
        .then((key) => {
            callback(null, key && (key.publicKey || key.rsaPublicKey));
        })
        .catch((err) => callback(err));
};

// the client secret for a given key is a signed JWT which is allowed to live
// for a relatively long time, so cache and re-use these to avoid unnecessary
// signature operations:
const clientSecretCache = new Map();

class AppleStrategy extends passport.Strategy {
    /**
     * @param {object} options
     * @param {string} options.clientID
     * @param {string} options.teamID
     * @param {string} options.keyID
     * @param {string} options.key
     * @param {string} options.keyFilePath
     * @param {string} [options.authorizationURL=https://appleid.apple.com/auth/authorize]
     * @param {string} [options.tokenURL=https://appleid.apple.com/auth/token]
     * @param {string} [options.revokeURL=https://appleid.apple.com/auth/revoke]
     * @param {Array<string>} [options.scope]
     * @param {string} [options.sessionKey]
     * @param {boolean} [options.state]
     * @param {boolean} [options.passReqToCallback=false]
     * @param {string} [options.callbackURL]
     * @param {function} verify
     */
    constructor(options = {}, verify) {
        if (!verify) throw new TypeError('AppleStrategy requires a verify callback');
        if (!options.clientID) throw new TypeError('AppleStrategy requires a clientID option');
        if (!options.teamID) throw new TypeError('AppleStrategy requires a teamID option');
        if (!options.keyID) throw new TypeError('AppleStrategy requires a keyID option');
        if (!options.key && !options.keyFilePath) throw new TypeError('AppleStrategy requires either the key or keyFilePath option');

        super();
        this.name = 'apple';
        this._verify = verify;

        this._clientID = options.clientID;
        this._teamID = options.teamID;
        this._keyID = options.keyID;
        
        if(options.keyFilePath) {
            this._key = fs.readFileSync(options.keyFilePath);
        } else {
            this._key = options.key
        }
        
        this._authorizationURL = options.authorizationURL || 'https://appleid.apple.com/auth/authorize';
        this._tokenURL = options.tokenURL || 'https://appleid.apple.com/auth/token';
        this._revokeURL = options.revokeURL || 'https://appleid.apple.com/auth/revoke';
        this._callbackURL = options.callbackURL;
        this._scope = options.scope;
        this._sessionKey = options.sessionKey || 'apple:' + new URL(this._authorizationURL).hostname;
        this._clientSecretExpiry = options.clientSecretExpiry || '5 minutes';
        this._verifyNonce = options.verifyNonce;

        if (options.state) {
            this._stateStore = new SessionStateStore({ key: this._sessionKey });
        } else {
            this._stateStore = new NullStateStore();
        }

        this._passReqToCallback = options.passReqToCallback;
    }

    verifyNonce(req, nonce_supported, nonce, callback) {
        if (this._verifyNonce && nonce_supported) {
            return this._verifyNonce(req, nonce, callback);
        } else {
            return callback(null, true);
        }
    }

    /**
     * @param {http.IncomingMessage} req
     * @param {object} [options]
     * @param {string} [options.callbackURL]
     * @param {Array<string>} [options.scope]
     * @param {string} [options.state]
     */
    authenticate(req, options = {}) {
        if (req.body && req.body.error) {
            if (req.body.error === 'user_cancelled_authorize') {
                return this.fail({ message: 'User cancelled authorize' });
            } else {
                return this.error(new AuthorizationError(req.body.error, req.body.error));
            }
        }

        let callbackURL = options.callbackURL || this._callbackURL;

        if (req.body && req.body.code) {
            const state = req.body.state;
            try {
                this._stateStore.verify(req, state, (err, ok, state) => {
                    if (err) return this.error(err);
                    if (!ok) return this.fail(state, 403);

                    const code = req.body.code;

                    const params = { grant_type: 'authorization_code' };
                    if (callbackURL) params.redirect_uri = callbackURL;

                    const oauth2 = this._getOAuth2Client();

                    oauth2.getOAuthAccessToken(code, params, (err, accessToken, refreshToken, params) => {
                        if (err) return this.error(this._createOAuthError('Failed to obtain access token', err));

                        const idToken = params['id_token'];
                        if (!idToken) return this.error(new Error('ID Token not present in token response'));

                        const verifyOpts = {
                            audience: this._clientID,
                            issuer: 'https://appleid.apple.com',
                            algorithms: ['RS256']
                        };
                        jwt.verify(idToken, getAppleJWKSKey, verifyOpts, (err, jwtClaims) => {
                            if (err) {
                                return this.error(err);
                            }

                            this.verifyNonce(req, jwtClaims.nonce_supported, jwtClaims.nonce, (err, ok) => {
                                if (err) return this.error(err);
                                if (!ok) return this.fail({ message: 'invalid nonce' });

                                let profile;
                                try {
                                    profile = this._buildProfile(jwtClaims, req.body.user);
                                } catch (ex) {
                                    return this.error(ex);
                                }

                                const verified = (err, user, info) => {
                                    if (err) return this.error(err);
                                    if (!user) return this.fail(info);

                                    info = info || {};
                                    if (state) info.state = state;
                                    this.success(user, info);
                                };

                                try {
                                    if (this._passReqToCallback) {
                                        this._verify(req, accessToken, refreshToken, profile, verified);
                                    } else {
                                        this._verify(accessToken, refreshToken, profile, verified);
                                    }
                                } catch (ex) {
                                    return this.error(ex);
                                }
                            });
                        });
                    });
                });
            } catch (ex) {
                return this.error(ex);
            }
        } else {
            const params = {
                client_id: this._clientID,
                response_type: 'code id_token',
                response_mode: 'form_post'
            };
            if (callbackURL) params.redirect_uri = callbackURL;
            let scope = options.scope || this._scope;
            if (scope) {
                params.scope = scope.join(' ');
            }

            if (options.nonce) {
                params.nonce = options.nonce;
            }

            const state = options.state;
            if (state) {
                params.state = state;
                this.redirect(this._authorizationURL + '?' + new URLSearchParams(params).toString());
            } else {
                this._stateStore.store(req, (err, state) => {
                    if (err) return this.error(err);

                    if (state) params.state = state;
                    this.redirect(this._authorizationURL + '?' + new URLSearchParams(params).toString());
                });
            }
        }
    }

    /**
     * Builds the profile object from verified ID token claims and the optional
     * `user` field Apple posts on the user's first authorization.
     *
     * Apple sends `email_verified` and `is_private_email` as either a boolean
     * or the strings 'true'/'false', so both forms are handled.
     *
     * @param {object} jwtClaims verified claims of the ID token
     * @param {object|string} [bodyUser] the `user` field of the callback request body
     * @returns {object} profile
     */
    _buildProfile(jwtClaims, bodyUser) {
        const asBool = (value) => value === true || value === 'true';

        const profile = { id: jwtClaims.sub, provider: 'apple' };

        if (jwtClaims.email) {
            profile.email = jwtClaims.email;
        }

        if (jwtClaims.email_verified !== undefined) {
            profile.emailVerified = asBool(jwtClaims.email_verified);
        }

        if (jwtClaims.is_private_email !== undefined) {
            profile.isPrivateEmail = asBool(jwtClaims.is_private_email);
        }

        if (bodyUser) {
            if (typeof bodyUser === 'object' && bodyUser.name) {
                profile.name = bodyUser.name;
            } else if (typeof bodyUser === 'string') {
                const user = JSON.parse(bodyUser);
                if (user && user.name) profile.name = user.name;
            }
        }

        return profile;
    }

    /**
     * Verifies a Sign in with Apple identity token against Apple's public keys
     * and returns its claims. Useful for backends that receive the identity
     * token directly from a native iOS/macOS app instead of the web flow.
     *
     * @param {string} idToken identity token (JWT) issued by Apple
     * @param {object} [options]
     * @param {string|Array<string>} [options.audience] expected audience; defaults to the configured clientID
     * @returns {Promise<object>} the verified token claims
     */
    verifyIdToken(idToken, options = {}) {
        return new Promise((resolve, reject) => {
            const verifyOpts = {
                audience: options.audience || this._clientID,
                issuer: 'https://appleid.apple.com',
                algorithms: ['RS256']
            };
            jwt.verify(idToken, getAppleJWKSKey, verifyOpts, (err, jwtClaims) => {
                if (err) return reject(err);
                resolve(jwtClaims);
            });
        });
    }

    /**
     * Exchanges a refresh token for a new access token, verifying that the
     * user's Apple session is still valid. Apple recommends doing this at most
     * once a day per user.
     *
     * @param {string} refreshToken refresh token obtained during authorization
     * @returns {Promise<object>} token response ({ access_token, token_type, expires_in, id_token })
     */
    async refreshAccessToken(refreshToken) {
        return this._tokenRequest(this._tokenURL, {
            client_id: this._clientID,
            client_secret: this._getClientSecret(),
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        }, 'Failed to refresh access token');
    }

    /**
     * Revokes a user's refresh or access token, invalidating the associated
     * user session. Required for account deletion flows per App Store Review
     * Guideline 5.1.1(v).
     *
     * @param {string} token refresh token or access token to revoke
     * @param {string} [tokenTypeHint=refresh_token] either 'refresh_token' or 'access_token'
     * @returns {Promise<void>}
     */
    async revokeToken(token, tokenTypeHint = 'refresh_token') {
        await this._tokenRequest(this._revokeURL, {
            client_id: this._clientID,
            client_secret: this._getClientSecret(),
            token,
            token_type_hint: tokenTypeHint
        }, 'Failed to revoke token');
    }

    /**
     * @param {string} endpoint
     * @param {object} form
     * @param {string} errorMessage
     * @returns {Promise<object|undefined>} parsed JSON body, if any
     */
    async _tokenRequest(endpoint, form, errorMessage) {
        const res = await fetch(endpoint, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams(form).toString()
        });

        const body = await res.text();
        if (!res.ok) {
            throw this._createOAuthError(errorMessage, { statusCode: res.status, data: body });
        }
        if (!body) return undefined;
        return JSON.parse(body);
    }

    /**
     * @param {string} body
     * @returns {Error}
     */
    parseErrorResponse(body) {
        const json = JSON.parse(body);
        if (json.error) {
            return new TokenError(json.error_description, json.error, json.error_uri);
        }
        return null;
    }

    /**
     * @returns {jwt|string} signed jwt client secret
     */
    _getClientSecret() {
        // if our current secret has expired (with a few seconds grace), or
        // hasn't been generated yet, regenerate it:
        const existing = clientSecretCache.get(this._keyID);
        if (!existing || jwt.decode(existing).exp < Date.now() / 1000 + 5) {
            clientSecretCache.set(
                this._keyID,
                jwt.sign({}, this._key, {
                    algorithm: 'ES256',
                    keyid: this._keyID,
                    expiresIn: this._clientSecretExpiry,
                    issuer: this._teamID,
                    audience: 'https://appleid.apple.com',
                    subject: this._clientID
                })
            );
        }
        return clientSecretCache.get(this._keyID);
    }

    /**
     * @returns {oauth2.OAuth2}
     */
    _getOAuth2Client() {
        return new OAuth2(this._clientID, this._getClientSecret(), '', this._authorizationURL, this._tokenURL);
    }

    /**
     * @param {string} message
     * @param {object|Error} err
     * @returns {Error}
     */
    _createOAuthError(message, err) {
        let e;
        if (err.statusCode && err.data) {
            try {
                e = this.parseErrorResponse(err.data);
            } catch (_) {
                // ignore
            }
        }
        if (!e) e = new InternalOAuthError(message, err);
        return e;
    }
}

module.exports = AppleStrategy;
