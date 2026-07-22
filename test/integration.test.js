const { test, describe, before, after } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const http = require('http');
const jwt = require('jsonwebtoken');

const AppleStrategy = require('../src/strategy');

// A local stand-in for Apple's servers: issues RS256-signed ID tokens from
// /auth/token and publishes the matching public key on /auth/keys, mirroring
// the real endpoints' contracts.
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const CLIENT_KEY = ec.privateKey.export({ type: 'pkcs8', format: 'pem' });
const KID = 'test-kid-1';
const CLIENT_ID = 'com.example.service';

const signIdToken = (claims) =>
    jwt.sign(
        {
            iss: 'https://appleid.apple.com',
            aud: CLIENT_ID,
            sub: 'apple-user-001',
            ...claims
        },
        rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }),
        { algorithm: 'RS256', keyid: KID, expiresIn: '10m' }
    );

let server;
let baseURL;
let tokenRequests;

const buildStrategy = (verify) =>
    new AppleStrategy(
        {
            clientID: CLIENT_ID,
            teamID: 'TEAMID1234',
            keyID: 'KEYID12345',
            key: CLIENT_KEY,
            callbackURL: 'https://example.com/oauth/apple/callback',
            tokenURL: `${baseURL}/auth/token`,
            jwksURL: `${baseURL}/auth/keys`
        },
        verify
    );

before(async () => {
    tokenRequests = [];
    server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => (body += chunk));
        req.on('end', () => {
            if (req.method === 'GET' && req.url === '/auth/keys') {
                const jwk = rsa.publicKey.export({ format: 'jwk' });
                res.setHeader('content-type', 'application/json');
                res.end(JSON.stringify({ keys: [{ ...jwk, kid: KID, use: 'sig', alg: 'RS256' }] }));
            } else if (req.method === 'POST' && req.url === '/auth/token') {
                tokenRequests.push(new URLSearchParams(body));
                res.setHeader('content-type', 'application/json');
                res.end(
                    JSON.stringify({
                        access_token: 'mock-access-token',
                        token_type: 'Bearer',
                        expires_in: 3600,
                        refresh_token: 'mock-refresh-token',
                        id_token: signIdToken({
                            email: 'user@privaterelay.appleid.com',
                            email_verified: true,
                            is_private_email: 'true'
                        })
                    })
                );
            } else {
                res.statusCode = 404;
                res.end();
            }
        });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseURL = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

describe('full authentication flow against a mock Apple server', () => {
    test('exchanges the code, verifies the ID token and builds the profile', (t, done) => {
        const strategy = buildStrategy((accessToken, refreshToken, profile, verified) => {
            try {
                assert.strictEqual(accessToken, 'mock-access-token');
                assert.strictEqual(refreshToken, 'mock-refresh-token');
                assert.strictEqual(profile.id, 'apple-user-001');
                assert.strictEqual(profile.provider, 'apple');
                assert.strictEqual(profile.email, 'user@privaterelay.appleid.com');
                assert.strictEqual(profile.emailVerified, true);
                assert.strictEqual(profile.isPrivateEmail, true);
                assert.deepStrictEqual(profile.name, { firstName: 'Jane', lastName: 'Doe' });
            } catch (err) {
                return done(err);
            }
            verified(null, { id: profile.id });
        });

        strategy.success = (user) => {
            try {
                assert.deepStrictEqual(user, { id: 'apple-user-001' });

                const tokenReq = tokenRequests[tokenRequests.length - 1];
                assert.strictEqual(tokenReq.get('grant_type'), 'authorization_code');
                assert.strictEqual(tokenReq.get('code'), 'mock-auth-code');
                assert.strictEqual(tokenReq.get('client_id'), CLIENT_ID);
                assert.strictEqual(tokenReq.get('redirect_uri'), 'https://example.com/oauth/apple/callback');

                const clientSecret = jwt.decode(tokenReq.get('client_secret'), { complete: true });
                assert.strictEqual(clientSecret.header.alg, 'ES256');
                assert.strictEqual(clientSecret.payload.aud, 'https://appleid.apple.com');
            } catch (err) {
                return done(err);
            }
            done();
        };
        strategy.fail = (info) => done(new Error('unexpected fail: ' + JSON.stringify(info)));
        strategy.error = done;

        strategy.authenticate({
            body: {
                code: 'mock-auth-code',
                user: JSON.stringify({ name: { firstName: 'Jane', lastName: 'Doe' } })
            }
        });
    });

    test('rejects an ID token issued for a different client', (t, done) => {
        const strategy = buildStrategy(() => done(new Error('verify should not be called')));
        strategy.success = () => done(new Error('should not succeed'));
        strategy.fail = () => done(new Error('should not fail silently'));
        strategy.error = (err) => {
            try {
                assert.match(err.message, /audience/i);
            } catch (assertErr) {
                return done(assertErr);
            }
            done();
        };

        strategy._clientID = 'com.other.app';
        strategy.authenticate({ body: { code: 'mock-auth-code' } });
    });

    test('verifyIdToken resolves claims for a valid native-app token', async () => {
        const strategy = buildStrategy(() => {});
        const claims = await strategy.verifyIdToken(
            signIdToken({ email: 'native@example.com', email_verified: 'true' })
        );
        assert.strictEqual(claims.sub, 'apple-user-001');
        assert.strictEqual(claims.email, 'native@example.com');
        assert.strictEqual(claims.iss, 'https://appleid.apple.com');
    });

    test('verifyIdToken rejects a token signed with an unknown key', async () => {
        const strategy = buildStrategy(() => {});
        const rogue = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const forged = jwt.sign(
            { iss: 'https://appleid.apple.com', aud: CLIENT_ID, sub: 'attacker' },
            rogue.privateKey.export({ type: 'pkcs1', format: 'pem' }),
            { algorithm: 'RS256', keyid: 'unknown-kid', expiresIn: '10m' }
        );
        await assert.rejects(() => strategy.verifyIdToken(forged));
    });

    test('verifyIdToken rejects an expired token', async () => {
        const strategy = buildStrategy(() => {});
        const expired = jwt.sign(
            { iss: 'https://appleid.apple.com', aud: CLIENT_ID, sub: 'apple-user-001' },
            rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }),
            { algorithm: 'RS256', keyid: KID, expiresIn: '-1m' }
        );
        await assert.rejects(() => strategy.verifyIdToken(expired), /expired/i);
    });
});

describe('verifyIdToken nonce verification', () => {
    test('resolves when the nonce matches', async () => {
        const strategy = buildStrategy(() => {});
        const claims = await strategy.verifyIdToken(signIdToken({ nonce: 'expected-nonce' }), {
            nonce: 'expected-nonce'
        });
        assert.strictEqual(claims.nonce, 'expected-nonce');
    });

    test('rejects when the nonce does not match', async () => {
        const strategy = buildStrategy(() => {});
        await assert.rejects(
            () => strategy.verifyIdToken(signIdToken({ nonce: 'tampered' }), { nonce: 'expected-nonce' }),
            /nonce/i
        );
    });

    test('rejects when a nonce is expected but the token has none', async () => {
        const strategy = buildStrategy(() => {});
        await assert.rejects(() => strategy.verifyIdToken(signIdToken({}), { nonce: 'expected-nonce' }), /nonce/i);
    });
});

describe('verifyServerNotification', () => {
    const signNotification = (claims, opts = {}) =>
        jwt.sign(
            {
                iss: 'https://appleid.apple.com',
                aud: CLIENT_ID,
                jti: 'notification-id-1',
                ...claims
            },
            (opts.key || rsa.privateKey).export({ type: 'pkcs1', format: 'pem' }),
            { algorithm: 'RS256', keyid: opts.kid || KID, expiresIn: '10m' }
        );

    test('verifies a notification with events as a JSON string', async () => {
        const strategy = buildStrategy(() => {});
        const event = { type: 'consent-revoked', sub: 'apple-user-001', event_time: 1750000000000 };
        const notification = await strategy.verifyServerNotification(
            signNotification({ events: JSON.stringify(event) })
        );
        assert.deepStrictEqual(notification.events, event);
        assert.strictEqual(notification.aud, CLIENT_ID);
    });

    test('verifies a notification with events as an object', async () => {
        const strategy = buildStrategy(() => {});
        const event = {
            type: 'email-disabled',
            sub: 'apple-user-001',
            email: 'user@privaterelay.appleid.com',
            is_private_email: 'true',
            event_time: 1750000000000
        };
        const notification = await strategy.verifyServerNotification(signNotification({ events: event }));
        assert.deepStrictEqual(notification.events, event);
    });

    test('rejects a notification signed with an unknown key', async () => {
        const strategy = buildStrategy(() => {});
        const rogue = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const forged = signNotification(
            { events: JSON.stringify({ type: 'account-deleted', sub: 'x', event_time: 1 }) },
            { key: rogue.privateKey, kid: 'unknown-kid' }
        );
        await assert.rejects(() => strategy.verifyServerNotification(forged));
    });

    test('rejects a notification for a different audience', async () => {
        const strategy = buildStrategy(() => {});
        const other = jwt.sign(
            {
                iss: 'https://appleid.apple.com',
                aud: 'com.other.app',
                events: JSON.stringify({ type: 'account-deleted', sub: 'x', event_time: 1 })
            },
            rsa.privateKey.export({ type: 'pkcs1', format: 'pem' }),
            { algorithm: 'RS256', keyid: KID, expiresIn: '10m' }
        );
        await assert.rejects(() => strategy.verifyServerNotification(other), /audience/i);
    });
});
