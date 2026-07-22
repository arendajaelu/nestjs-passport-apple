const { test, describe, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const AppleStrategy = require('../src/strategy');
const AuthorizationError = require('../src/errors/authorizationerror');
const TokenError = require('../src/errors/tokenerror');

const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const TEST_KEY = privateKey.export({ type: 'pkcs8', format: 'pem' });

const buildStrategy = (options = {}, verify = () => {}) =>
    new AppleStrategy(
        {
            clientID: 'com.example.app',
            teamID: 'TEAMID1234',
            keyID: 'KEYID12345',
            key: TEST_KEY,
            ...options
        },
        verify
    );

describe('constructor', () => {
    test('throws without a verify callback', () => {
        assert.throws(() => new AppleStrategy({ clientID: 'x', teamID: 'x', keyID: 'x', key: TEST_KEY }), TypeError);
    });

    test('throws without clientID', () => {
        assert.throws(() => buildStrategy({ clientID: undefined }), /clientID/);
    });

    test('throws without teamID', () => {
        assert.throws(() => buildStrategy({ teamID: undefined }), /teamID/);
    });

    test('throws without keyID', () => {
        assert.throws(() => buildStrategy({ keyID: undefined }), /keyID/);
    });

    test('throws without key or keyFilePath', () => {
        assert.throws(() => buildStrategy({ key: undefined }), /key or keyFilePath/);
    });

    test('is named apple', () => {
        assert.strictEqual(buildStrategy().name, 'apple');
    });
});

describe('authenticate: authorization redirect', () => {
    test('redirects to Apple with expected parameters', (t, done) => {
        const strategy = buildStrategy({ scope: ['email', 'name'], callbackURL: 'https://example.com/cb' });
        strategy.redirect = (location) => {
            const parsed = new URL(location);
            assert.strictEqual(parsed.origin + parsed.pathname, 'https://appleid.apple.com/auth/authorize');
            assert.strictEqual(parsed.searchParams.get('client_id'), 'com.example.app');
            assert.strictEqual(parsed.searchParams.get('response_type'), 'code id_token');
            assert.strictEqual(parsed.searchParams.get('response_mode'), 'form_post');
            assert.strictEqual(parsed.searchParams.get('scope'), 'email name');
            assert.strictEqual(parsed.searchParams.get('redirect_uri'), 'https://example.com/cb');
            done();
        };
        strategy.error = done;
        strategy.authenticate({});
    });
});

describe('authenticate: error responses from Apple', () => {
    test('fails gracefully when the user cancels', (t, done) => {
        const strategy = buildStrategy();
        strategy.fail = (info) => {
            assert.match(info.message, /cancelled/i);
            done();
        };
        strategy.error = done;
        strategy.authenticate({ body: { error: 'user_cancelled_authorize' } });
    });

    test('produces an AuthorizationError with a message for other errors', (t, done) => {
        const strategy = buildStrategy();
        strategy.error = (err) => {
            assert.ok(err instanceof AuthorizationError);
            assert.strictEqual(err.message, 'access_denied');
            assert.strictEqual(err.status, 403);
            done();
        };
        strategy.authenticate({ body: { error: 'access_denied' } });
    });
});

describe('profile parsing', () => {
    const strategy = buildStrategy();

    test('handles email_verified as string', () => {
        const profile = strategy._buildProfile({ sub: 'user1', email: 'a@b.c', email_verified: 'true' });
        assert.strictEqual(profile.emailVerified, true);
    });

    test('handles email_verified as boolean', () => {
        const profile = strategy._buildProfile({ sub: 'user1', email: 'a@b.c', email_verified: true });
        assert.strictEqual(profile.emailVerified, true);
    });

    test('handles is_private_email in both forms', () => {
        assert.strictEqual(strategy._buildProfile({ sub: 'u', is_private_email: 'true' }).isPrivateEmail, true);
        assert.strictEqual(strategy._buildProfile({ sub: 'u', is_private_email: false }).isPrivateEmail, false);
    });

    test('omits claims that are not present', () => {
        const profile = strategy._buildProfile({ sub: 'user1' });
        assert.deepStrictEqual(profile, { id: 'user1', provider: 'apple' });
    });

    test('parses the name from a JSON string body field', () => {
        const bodyUser = JSON.stringify({ name: { firstName: 'Jane', lastName: 'Doe' } });
        const profile = strategy._buildProfile({ sub: 'user1' }, bodyUser);
        assert.deepStrictEqual(profile.name, { firstName: 'Jane', lastName: 'Doe' });
    });

    test('accepts an already-parsed user object', () => {
        const profile = strategy._buildProfile({ sub: 'user1' }, { name: { firstName: 'Jane', lastName: 'Doe' } });
        assert.deepStrictEqual(profile.name, { firstName: 'Jane', lastName: 'Doe' });
    });

    test('throws on malformed user JSON', () => {
        assert.throws(() => strategy._buildProfile({ sub: 'user1' }, '{not json'));
    });
});

describe('token endpoint helpers', () => {
    const originalFetch = global.fetch;
    let requests;

    beforeEach(() => {
        requests = [];
    });

    afterEach(() => {
        global.fetch = originalFetch;
    });

    const mockFetch = (status, body) => {
        global.fetch = async (endpoint, init) => {
            requests.push({ endpoint, init });
            return {
                ok: status >= 200 && status < 300,
                status,
                text: async () => body
            };
        };
    };

    test('revokeToken posts the expected form and resolves on 200', async () => {
        mockFetch(200, '');
        const strategy = buildStrategy();
        await strategy.revokeToken('some-refresh-token');

        assert.strictEqual(requests.length, 1);
        assert.strictEqual(requests[0].endpoint, 'https://appleid.apple.com/auth/revoke');
        const form = new URLSearchParams(requests[0].init.body);
        assert.strictEqual(form.get('client_id'), 'com.example.app');
        assert.strictEqual(form.get('token'), 'some-refresh-token');
        assert.strictEqual(form.get('token_type_hint'), 'refresh_token');
        assert.ok(form.get('client_secret'));
    });

    test('revokeToken accepts an access_token hint', async () => {
        mockFetch(200, '');
        const strategy = buildStrategy();
        await strategy.revokeToken('some-access-token', 'access_token');
        assert.strictEqual(new URLSearchParams(requests[0].init.body).get('token_type_hint'), 'access_token');
    });

    test('revokeToken throws a TokenError on an OAuth error response', async () => {
        mockFetch(400, JSON.stringify({ error: 'invalid_client', error_description: 'bad secret' }));
        const strategy = buildStrategy();
        await assert.rejects(() => strategy.revokeToken('bad-token'), (err) => {
            assert.ok(err instanceof TokenError);
            assert.strictEqual(err.code, 'invalid_client');
            return true;
        });
    });

    test('refreshAccessToken posts a refresh_token grant and returns the token response', async () => {
        const tokenResponse = { access_token: 'at', token_type: 'Bearer', expires_in: 3600, id_token: 'idt' };
        mockFetch(200, JSON.stringify(tokenResponse));
        const strategy = buildStrategy();
        const result = await strategy.refreshAccessToken('some-refresh-token');

        assert.deepStrictEqual(result, tokenResponse);
        assert.strictEqual(requests[0].endpoint, 'https://appleid.apple.com/auth/token');
        const form = new URLSearchParams(requests[0].init.body);
        assert.strictEqual(form.get('grant_type'), 'refresh_token');
        assert.strictEqual(form.get('refresh_token'), 'some-refresh-token');
    });

    test('refreshAccessToken throws a TokenError when the grant is rejected', async () => {
        mockFetch(400, JSON.stringify({ error: 'invalid_grant', error_description: 'revoked' }));
        const strategy = buildStrategy();
        await assert.rejects(() => strategy.refreshAccessToken('revoked-token'), (err) => {
            assert.ok(err instanceof TokenError);
            assert.strictEqual(err.code, 'invalid_grant');
            return true;
        });
    });
});

describe('client secret', () => {
    test('generates an ES256 JWT with the expected claims', () => {
        const strategy = buildStrategy();
        const secret = strategy._getClientSecret();
        const decoded = require('jsonwebtoken').decode(secret, { complete: true });

        assert.strictEqual(decoded.header.alg, 'ES256');
        assert.strictEqual(decoded.header.kid, 'KEYID12345');
        assert.strictEqual(decoded.payload.iss, 'TEAMID1234');
        assert.strictEqual(decoded.payload.sub, 'com.example.app');
        assert.strictEqual(decoded.payload.aud, 'https://appleid.apple.com');
    });

    test('reuses the cached secret until it expires', () => {
        const strategy = buildStrategy();
        assert.strictEqual(strategy._getClientSecret(), strategy._getClientSecret());
    });
});

describe('verifyIdToken', () => {
    test('rejects a malformed token', async () => {
        const strategy = buildStrategy();
        await assert.rejects(() => strategy.verifyIdToken('not-a-jwt'));
    });
});

describe('client secret lifecycle', () => {
    test('generates a fresh client secret after the previous one expires', (t) => {
        t.mock.timers.enable({ apis: ['Date'], now: 1_750_000_000_000 });
        const strategy = buildStrategy({ clientID: 'com.example.expiry', clientSecretExpiry: '60 seconds' });

        const first = strategy._getClientSecret();
        assert.strictEqual(strategy._getClientSecret(), first);

        t.mock.timers.setTime(1_750_000_000_000 + 120 * 1000);
        const second = strategy._getClientSecret();
        assert.notStrictEqual(second, first);

        const decoded = require('jsonwebtoken').decode(second);
        assert.ok(decoded.exp > 1_750_000_000_000 / 1000 + 120);
    });

    test('caches secrets separately per clientID even with the same keyID', () => {
        const a = buildStrategy({ clientID: 'com.example.appA' });
        const b = buildStrategy({ clientID: 'com.example.appB' });

        const secretA = a._getClientSecret();
        const secretB = b._getClientSecret();

        assert.notStrictEqual(secretA, secretB);
        const jwt = require('jsonwebtoken');
        assert.strictEqual(jwt.decode(secretA).sub, 'com.example.appA');
        assert.strictEqual(jwt.decode(secretB).sub, 'com.example.appB');
    });
});

describe('state store', () => {
    test('uses a custom store when provided', (t, done) => {
        const calls = [];
        const store = {
            store(req, cb) {
                calls.push('store');
                cb(null, 'custom-state-value');
            },
            verify(req, providedState, cb) {
                calls.push('verify:' + providedState);
                cb(null, true);
            }
        };
        const strategy = buildStrategy({ store });

        strategy.redirect = (location) => {
            assert.strictEqual(new URL(location).searchParams.get('state'), 'custom-state-value');
            assert.deepStrictEqual(calls, ['store']);
            done();
        };
        strategy.error = done;
        strategy.authenticate({});
    });

    test('state:true rejects a callback whose state does not match the session', (t, done) => {
        const strategy = buildStrategy({ state: true });
        const req = {
            session: { 'apple:appleid.apple.com': { state: 'stored-state' } },
            body: { code: 'some-code', state: 'attacker-state' }
        };
        strategy.fail = (info, status) => {
            assert.strictEqual(status, 403);
            assert.match(info.message, /state/i);
            done();
        };
        strategy.error = done;
        strategy.success = () => done(new Error('should not succeed'));
        strategy.authenticate(req);
    });

    test('state:true errors clearly when session support is missing', (t, done) => {
        const strategy = buildStrategy({ state: true });
        strategy.error = (err) => {
            assert.match(err.message, /session/i);
            done();
        };
        strategy.authenticate({});
    });
});
