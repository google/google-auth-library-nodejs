// Copyright 2013 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import * as assert from 'assert';
import {describe, it, beforeEach, afterEach} from 'mocha';
import * as fs from 'fs';
import * as jws from 'jws';
import * as nock from 'nock';
import * as sinon from 'sinon';

import {GoogleAuth, JWT} from '../src';
import {CredentialRequest, JWTInput} from '../src/auth/credentials';
import * as jwtaccess from '../src/auth/jwtaccess';

describe('jwt', () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const keypair = require('keypair');
  const PEM_PATH = './test/fixtures/private.pem';
  const PEM_CONTENTS = fs.readFileSync(PEM_PATH, 'utf8');
  const P12_PATH = './test/fixtures/key.p12';

  nock.disableNetConnect();

  // Creates a standard JSON credentials object for testing.
  function createJSON() {
    return {
      private_key_id: 'key123',
      private_key: 'privatekey',
      client_email: 'hello@youarecool.com',
      client_id: 'client123',
      type: 'service_account',
    };
  }

  function createRefreshJSON() {
    return {
      client_secret: 'privatekey',
      client_id: 'client123',
      refresh_token: 'refreshtoken',
      type: 'authorized_user',
    };
  }

  function createGTokenMock(body: CredentialRequest) {
    return nock('https://www.googleapis.com')
      .post('/oauth2/v4/token')
      .reply(200, body);
  }

  // set up the test json and the jwt instance being tested.
  let jwt: JWT;
  let json: JWTInput;
  let sandbox: sinon.SinonSandbox;
  beforeEach(() => {
    json = createJSON();
    jwt = new JWT();
    sandbox = sinon.createSandbox();
  });

  afterEach(() => {
    nock.cleanAll();
    sandbox.restore();
  });

  it('should create a dummy refresh token string', () => {
    // It is important that the compute client is created with a refresh token
    // value filled in, or else the rest of the logic will not work.
    const jwt = new JWT();
    assert.strictEqual('jwt-placeholder', jwt.credentials.refresh_token);
  });

  it('should get an initial access token', done => {
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const scope = createGTokenMock({access_token: 'initial-access-token'});
    jwt.authorize((err, creds) => {
      scope.done();
      assert.strictEqual(err, null);
      assert.notStrictEqual(creds, null);
      assert.strictEqual('foo@serviceaccount.com', jwt.gtoken!.iss);
      assert.strictEqual(PEM_PATH, jwt.gtoken!.keyFile);
      assert.strictEqual(
        ['http://bar', 'http://foo'].join(' '),
        jwt.gtoken!.scope
      );
      assert.strictEqual('bar@subjectaccount.com', jwt.gtoken!.sub);
      assert.strictEqual('initial-access-token', jwt.credentials.access_token);
      assert.strictEqual(creds!.access_token, jwt.credentials.access_token);
      assert.strictEqual(creds!.refresh_token, jwt.credentials.refresh_token);
      assert.strictEqual(creds!.token_type, jwt.credentials.token_type);
      assert.strictEqual('jwt-placeholder', jwt.credentials.refresh_token);
      assert.strictEqual(PEM_CONTENTS, jwt.key);
      assert.strictEqual('foo@serviceaccount.com', jwt.email);
      done();
    });
  });

  it('should accept scope as string', done => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: 'http://foo',
      subject: 'bar@subjectaccount.com',
    });
    const scope = createGTokenMock({access_token: 'initial-access-token'});

    jwt.authorize(() => {
      scope.done();
      assert.strictEqual('http://foo', jwt.gtoken!.scope);
      done();
    });
  });

  it('can get obtain new access token when scopes are set', done => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {refresh_token: 'jwt-placeholder'};
    const scope = createGTokenMock({access_token: 'initial-access-token'});
    jwt.getAccessToken((err, got) => {
      scope.done();
      assert.strictEqual(null, err, 'no error was expected: got\n' + err);
      assert.strictEqual(
        'initial-access-token',
        got,
        'the access token was wrong: ' + got
      );
      done();
    });
  });

  it('should emit an event for tokens', done => {
    const accessToken = 'initial-access-token';
    const scope = createGTokenMock({access_token: accessToken});
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    jwt
      .on('tokens', tokens => {
        assert.strictEqual(tokens.access_token, accessToken);
        scope.done();
        done();
      })
      .getAccessToken();
  });

  it('can obtain new access token when scopes are set', async () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const wantedToken = 'abc123';
    const want = `Bearer ${wantedToken}`;
    const scope = createGTokenMock({access_token: wantedToken});
    const headers = await jwt.getRequestHeaders();
    scope.done();
    assert.strictEqual(
      want,
      headers.Authorization,
      `the authorization header was wrong: ${headers.Authorization}`
    );
  });

  it('gets a jwt header access token', async () => {
    const keys = keypair(512 /* bitsize of private key */);
    const email = 'foo@serviceaccount.com';
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: keys.private,
      subject: 'ignored@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const testUri = 'http:/example.com/my_test_service';
    const got = await jwt.getRequestHeaders(testUri);
    assert.notStrictEqual(null, got, 'the creds should be present');
    const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
    assert.deepStrictEqual({alg: 'RS256', typ: 'JWT'}, decoded.header);
    const payload = decoded.payload;
    assert.strictEqual(email, payload.iss);
    assert.strictEqual(email, payload.sub);
    assert.strictEqual(testUri, payload.aud);
  });

  it('gets a jwt header access token with key id', async () => {
    const keys = keypair(512 /* bitsize of private key */);
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: keys.private,
      keyId: '101',
      subject: 'ignored@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const testUri = 'http:/example.com/my_test_service';
    const got = await jwt.getRequestHeaders(testUri);
    assert.notStrictEqual(null, got, 'the creds should be present');
    const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
    assert.deepStrictEqual(
      {alg: 'RS256', typ: 'JWT', kid: '101'},
      decoded.header
    );
  });

  it('should accept additionalClaims', async () => {
    const keys = keypair(512 /* bitsize of private key */);
    const someClaim = 'cat-on-my-desk';
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: keys.private,
      subject: 'ignored@subjectaccount.com',
      additionalClaims: {someClaim},
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const testUri = 'http:/example.com/my_test_service';
    const got = await jwt.getRequestHeaders(testUri);
    assert.notStrictEqual(null, got, 'the creds should be present');
    const decoded = jws.decode(got.Authorization.replace('Bearer ', ''));
    const payload = decoded.payload;
    assert.strictEqual(testUri, payload.aud);
    assert.strictEqual(someClaim, payload.someClaim);
  });

  it('should accept additionalClaims that include a target_audience', async () => {
    const keys = keypair(512 /* bitsize of private key */);
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: keys.private,
      subject: 'ignored@subjectaccount.com',
      additionalClaims: {target_audience: 'applause'},
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const testUri = 'http:/example.com/my_test_service';
    const scope = createGTokenMock({id_token: 'abc123'});
    const got = await jwt.getRequestHeaders(testUri);
    scope.done();
    assert.notStrictEqual(null, got, 'the creds should be present');
    const decoded = got.Authorization.replace('Bearer ', '');
    assert.strictEqual(decoded, 'abc123');
  });

  it('should refresh token if missing access token', done => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};
    const scope = createGTokenMock({access_token: 'abc123'});

    jwt.request({url: 'http://bar'}, () => {
      scope.done();
      assert.strictEqual('abc123', jwt.credentials.access_token);
      done();
    });
  });

  it('should unify the promise when refreshing the token', async () => {
    // Mock a single call to the token server, and 3 calls to the example
    // endpoint. This makes sure that refreshToken is called only once.
    const scopes = [
      createGTokenMock({access_token: 'abc123'}),
      nock('http://example.com').get('/').thrice().reply(200),
    ];
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'jwt-placeholder'};
    await Promise.all([
      jwt.request({url: 'http://example.com'}),
      jwt.request({url: 'http://example.com'}),
      jwt.request({url: 'http://example.com'}),
    ]);
    scopes.forEach(s => s.done());
    assert.strictEqual('abc123', jwt.credentials.access_token);
  });

  it('should clear the cached refresh token promise after completion', async () => {
    // Mock 2 calls to the token server and 2 calls to the example endpoint.
    // This makes sure that the token endpoint is invoked twice, preventing
    // the promise from getting cached for too long.
    const scopes = [
      createGTokenMock({access_token: 'abc123'}),
      createGTokenMock({access_token: 'abc123'}),
      nock('http://example.com').get('/').twice().reply(200),
    ];
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    jwt.credentials = {refresh_token: 'refresh-token-placeholder'};
    await jwt.request({url: 'http://example.com'});
    jwt.credentials.access_token = null;
    await jwt.request({url: 'http://example.com'});
    scopes.forEach(s => s.done());
    assert.strictEqual('abc123', jwt.credentials.access_token);
  });

  it('should refresh token if expired', done => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {
      access_token: 'woot',
      refresh_token: 'jwt-placeholder',
      expiry_date: new Date().getTime() - 1000,
    };

    const scope = createGTokenMock({access_token: 'abc123'});
    jwt.request({url: 'http://bar'}, () => {
      scope.done();
      assert.strictEqual('abc123', jwt.credentials.access_token);
      done();
    });
  });

  it('should refresh if access token will expired soon and time to refresh before expiration is set', done => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
      eagerRefreshThresholdMillis: 1000,
    });

    jwt.credentials = {
      access_token: 'woot',
      refresh_token: 'jwt-placeholder',
      expiry_date: new Date().getTime() + 800,
    };

    const scope = createGTokenMock({access_token: 'abc123'});
    jwt.request({url: 'http://bar'}, () => {
      scope.done();
      assert.strictEqual('abc123', jwt.credentials.access_token);
      done();
    });
  });

  it('should not refresh if access token will not expire soon and time to refresh before expiration is set', done => {
    const scope = createGTokenMock({access_token: 'abc123', expires_in: 10000});
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
      eagerRefreshThresholdMillis: 1000,
    });

    jwt.credentials = {
      access_token: 'initial-access-token',
      refresh_token: 'jwt-placeholder',
      expiry_date: new Date().getTime() + 5000,
    };

    jwt.request({url: 'http://bar'}, () => {
      assert.strictEqual('initial-access-token', jwt.credentials.access_token);
      assert.strictEqual(false as boolean, scope.isDone());
      done();
    });
  });

  it('should refresh token if the server returns 403', done => {
    nock('http://example.com').get('/access').twice().reply(403);
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://example.com'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {
      access_token: 'woot',
      refresh_token: 'jwt-placeholder',
      expiry_date: new Date().getTime() + 5000,
    };

    const scope = createGTokenMock({access_token: 'abc123'});

    jwt.request({url: 'http://example.com/access'}, () => {
      scope.done();
      assert.strictEqual('abc123', jwt.credentials.access_token);
      done();
    });
  });

  it('should not refresh if not expired', done => {
    const scope = createGTokenMock({access_token: 'abc123', expires_in: 10000});
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {
      access_token: 'initial-access-token',
      refresh_token: 'jwt-placeholder',
      expiry_date: new Date().getTime() + 5000,
    };

    jwt.request({url: 'http://bar'}, () => {
      assert.strictEqual('initial-access-token', jwt.credentials.access_token);
      assert.strictEqual(false as boolean, scope.isDone());
      done();
    });
  });

  it('should assume access token is not expired', done => {
    const scope = createGTokenMock({access_token: 'abc123', expires_in: 10000});
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {
      access_token: 'initial-access-token',
      refresh_token: 'jwt-placeholder',
    };

    jwt.request({url: 'http://bar'}, () => {
      assert.strictEqual('initial-access-token', jwt.credentials.access_token);
      assert.strictEqual(false as boolean, scope.isDone());
      done();
    });
  });

  it('should return expiry_date in milliseconds', async () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: PEM_PATH,
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    jwt.credentials = {refresh_token: 'jwt-placeholder'};

    const scope = createGTokenMock({access_token: 'token', expires_in: 100});
    jwt.credentials.access_token = null;
    await jwt.getRequestHeaders();
    scope.done();
    const dateInMillis = new Date().getTime();
    assert.strictEqual(
      dateInMillis.toString().length,
      jwt.credentials.expiry_date!.toString().length
    );
  });

  it('createScoped should clone stuff', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      keyId: '101',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });

    const clone = jwt.createScoped('x');

    assert.strictEqual(jwt.email, clone.email);
    assert.strictEqual(jwt.keyFile, clone.keyFile);
    assert.strictEqual(jwt.key, clone.key);
    assert.strictEqual(jwt.keyId, clone.keyId);
    assert.strictEqual(jwt.subject, clone.subject);
  });

  it('createScoped should handle string scope', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    const clone = jwt.createScoped('newscope');
    assert.strictEqual('newscope', clone.scopes);
  });

  it('createScoped should handle array scope', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    const clone = jwt.createScoped(['gorilla', 'chimpanzee', 'orangutan']);
    assert.strictEqual(3, clone.scopes!.length);
    assert.strictEqual('gorilla', clone.scopes![0]);
    assert.strictEqual('chimpanzee', clone.scopes![1]);
    assert.strictEqual('orangutan', clone.scopes![2]);
  });

  it('createScoped should handle null scope', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    const clone = jwt.createScoped();
    assert.strictEqual(undefined, clone.scopes);
  });

  it('createScoped should set scope when scope was null', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      subject: 'bar@subjectaccount.com',
    });
    const clone = jwt.createScoped('hi');
    assert.strictEqual('hi', clone.scopes);
  });

  it('createScoped should handle nulls', () => {
    const jwt = new JWT();
    const clone = jwt.createScoped('hi');
    assert.strictEqual(jwt.email, undefined);
    assert.strictEqual(jwt.keyFile, undefined);
    assert.strictEqual(jwt.key, undefined);
    assert.strictEqual(jwt.subject, undefined);
    assert.strictEqual('hi', clone.scopes);
  });

  it('createScoped should not return the original instance', () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      keyFile: '/path/to/key.pem',
      scopes: ['http://bar', 'http://foo'],
      subject: 'bar@subjectaccount.com',
    });
    const clone = jwt.createScoped('hi');
    assert.notStrictEqual(jwt, clone);
  });

  it('fromJson should error on null json', () => {
    assert.throws(() => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (jwt as any).fromJSON(null);
    });
  });

  it('fromJson should error on empty json', () => {
    assert.throws(() => {
      jwt.fromJSON({});
    });
  });

  it('fromJson should error on missing client_email', () => {
    delete json.client_email;
    assert.throws(() => {
      jwt.fromJSON(json);
    });
  });

  it('fromJson should error on missing private_key', () => {
    delete json.private_key;
    assert.throws(() => {
      jwt.fromJSON(json);
    });
  });

  it('fromJson should create JWT with client_email', () => {
    jwt.fromJSON(json);
    assert.strictEqual(json.client_email, jwt.email);
  });

  it('fromJson should create JWT with private_key', () => {
    jwt.fromJSON(json);
    assert.strictEqual(json.private_key, jwt.key);
  });

  it('fromJson should create JWT with private_key_id', () => {
    jwt.fromJSON(json);
    assert.strictEqual(json.private_key_id, jwt.keyId);
  });

  it('fromJson should create JWT with null scopes', () => {
    jwt.fromJSON(json);
    assert.strictEqual(undefined, jwt.scopes);
  });

  it('fromJson should create JWT with null subject', () => {
    jwt.fromJSON(json);
    assert.strictEqual(undefined, jwt.subject);
  });

  it('fromJson should create JWT with null keyFile', () => {
    jwt.fromJSON(json);
    assert.strictEqual(undefined, jwt.keyFile);
  });

  it('should error on missing client_id', () => {
    const json = createRefreshJSON();
    delete json.client_id;
    const jwt = new JWT();
    assert.throws(() => {
      jwt.fromJSON(json);
    });
  });

  it('should error on missing client_secret', () => {
    const json = createRefreshJSON();
    delete json.client_secret;
    const jwt = new JWT();
    assert.throws(() => {
      jwt.fromJSON(json);
    });
  });

  it('should error on missing refresh_token', () => {
    const json = createRefreshJSON();
    delete json.refresh_token;
    const jwt = new JWT();
    assert.throws(() => {
      jwt.fromJSON(json);
    });
  });

  it('fromStream should error on null stream', done => {
    // Test verifies invalid parameter tests, which requires cast to any.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (jwt as any).fromStream(null, (err: Error) => {
      assert.strictEqual(true, err instanceof Error);
      done();
    });
  });

  it('fromStream should read the stream and create a jwt', done => {
    // Read the contents of the file into a json object.
    const fileContents = fs.readFileSync(
      './test/fixtures/private.json',
      'utf-8'
    );
    const json = JSON.parse(fileContents);

    // Now open a stream on the same file.
    const stream = fs.createReadStream('./test/fixtures/private.json');

    // And pass it into the fromStream method.
    jwt.fromStream(stream, err => {
      assert.strictEqual(undefined, err);
      // Ensure that the correct bits were pulled from the stream.
      assert.strictEqual(json.private_key, jwt.key);
      assert.strictEqual(json.private_key_id, jwt.keyId);
      assert.strictEqual(json.client_email, jwt.email);
      assert.strictEqual(undefined, jwt.keyFile);
      assert.strictEqual(undefined, jwt.subject);
      assert.strictEqual(undefined, jwt.scopes);
      done();
    });
  });

  it('fromAPIKey should error without api key', () => {
    assert.throws(() => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (jwt as any).fromAPIKey(undefined);
    });
  });

  it('fromAPIKey should error with invalid api key type', () => {
    const KEY = 'test';
    assert.throws(() => {
      // Test verifies invalid parameter tests, which requires cast to any.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      jwt.fromAPIKey({key: KEY} as any);
    });
  });

  it('fromAPIKey should set the .apiKey property on the instance', () => {
    const KEY = 'test';
    jwt.fromAPIKey(KEY);
    assert.strictEqual(jwt.apiKey, KEY);
  });

  it('getCredentials should handle a key', async () => {
    const jwt = new JWT({key: PEM_CONTENTS});
    const {private_key} = await jwt.getCredentials();
    assert.strictEqual(private_key, PEM_CONTENTS);
  });

  it('getCredentials should handle a p12 keyFile', async () => {
    const jwt = new JWT({keyFile: P12_PATH});
    const {private_key, client_email} = await jwt.getCredentials();
    assert(private_key);
    assert.strictEqual(client_email, undefined);
  });

  it('getCredentials should handle a json keyFile', async () => {
    const jwt = new JWT();
    jwt.fromJSON(json);
    const {private_key, client_email} = await jwt.getCredentials();
    assert.strictEqual(private_key, json.private_key);
    assert.strictEqual(client_email, json.client_email);
  });

  it('getRequestHeaders populates x-goog-user-project for JWT client', async () => {
    const auth = new GoogleAuth({
      credentials: Object.assign(
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        require('../../test/fixtures/service-account-with-quota.json'),
        {
          private_key: keypair(512 /* bitsize of private key */).private,
        }
      ),
    });
    const client = await auth.getClient();
    assert(client instanceof JWT);
    // If a URL isn't provided to authorize, the OAuth2Client super class is
    // executed, which was already exercised.
    const headers = await client.getRequestHeaders(
      'http:/example.com/my_test_service'
    );
    assert.strictEqual(headers['x-goog-user-project'], 'fake-quota-project');
  });

  it('should return an ID token for fetchIdToken', async () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: PEM_CONTENTS,
      subject: 'ignored@subjectaccount.com',
    });

    const scope = createGTokenMock({id_token: 'abc123'});
    const idtoken = await jwt.fetchIdToken('a-target-audience');
    scope.done();
    assert.strictEqual(idtoken, 'abc123');
  });

  it('should throw an error if ID token is not set', async () => {
    const jwt = new JWT({
      email: 'foo@serviceaccount.com',
      key: PEM_CONTENTS,
      subject: 'ignored@subjectaccount.com',
    });

    const scope = createGTokenMock({access_token: 'a-token'});
    try {
      await jwt.fetchIdToken('a-target-audience');
    } catch {
      scope.done();
      return;
    }
    assert.fail('failed to throw');
  });

  describe('self-signed JWT', () => {
    afterEach(() => {
      sandbox.restore();
    });

    it('uses self signed JWT when useJWTAccessAlways is set', async () => {
      const stubJWTAccess = sandbox.stub(jwtaccess, 'JWTAccess').returns({
        getRequestHeaders: sinon.stub().returns({}),
      });
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      jwt.useJWTAccessAlways = true;
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledOnce(stubJWTAccess);
    });

    it('always passes default endpoint for useJWTAccessAlways', async () => {
      const stubJWTAccess = sandbox.spy(
        jwtaccess.JWTAccess.prototype,
        'getRequestHeaders'
      );
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      jwt.useJWTAccessAlways = true;
      jwt.defaultServicePath = 'a/b/c';
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledWith(stubJWTAccess, 'https://a/b/c/');
    });

    it('uses self signed JWT when no scopes are provided', async () => {
      const stubJWTAccess = sandbox.stub(jwtaccess, 'JWTAccess').returns({
        getRequestHeaders: sinon.stub().returns({}),
      });
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledOnce(stubJWTAccess);
    });

    it('uses self signed JWT when default scopes are provided', async () => {
      const JWTAccess = sandbox.stub(jwtaccess, 'JWTAccess').returns({
        getRequestHeaders: sinon.stub().returns({}),
      });
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        subject: 'bar@subjectaccount.com',
      });
      jwt.defaultScopes = ['http://bar', 'http://foo'];
      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledOnce(JWTAccess);
    });

    it('does not use self signed JWT if target_audience provided', async () => {
      const JWTAccess = sandbox.stub(jwtaccess, 'JWTAccess').returns({
        getRequestHeaders: sinon.stub().returns({}),
      });
      const keys = keypair(512 /* bitsize of private key */);
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: keys.private,
        subject: 'ignored@subjectaccount.com',
        additionalClaims: {target_audience: 'beepboop'},
      });
      jwt.defaultScopes = ['foo', 'bar'];
      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      const testUri = 'http:/example.com/my_test_service';
      const scope = createGTokenMock({id_token: 'abc123'});
      await jwt.getRequestHeaders(testUri);
      scope.done();
      sandbox.assert.notCalled(JWTAccess);
    });

    it('returns headers from cache, prior to their expiry time', async () => {
      const sign = sandbox.stub(jws, 'sign').returns('abc123');
      const getExpirationTime = sandbox
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .stub(jwtaccess.JWTAccess as any, 'getExpirationTime')
        .returns(Date.now() / 1000 + 3600); // expire in an hour.
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      // The second time we fetch headers should not cause getExpirationTime
      // to be invoked a second time:
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledOnce(getExpirationTime);
      sandbox.assert.calledOnce(sign);
    });

    it('creates a new self-signed JWT, if headers are close to expiring', async () => {
      const sign = sandbox.stub(jws, 'sign').returns('abc123');
      const getExpirationTime = sandbox
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        .stub(jwtaccess.JWTAccess as any, 'getExpirationTime')
        .returns(Date.now() / 1000 + 5); // expire in 5 seconds.
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      jwt.credentials = {refresh_token: 'jwt-placeholder'};
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      // The second time we fetch headers should not cause getExpirationTime
      // to be invoked a second time:
      await jwt.getRequestHeaders('https//beepboop.googleapis.com');
      sandbox.assert.calledTwice(getExpirationTime);
      sandbox.assert.calledTwice(sign);
    });

    it('returns no headers when no scopes or audiences are provided', async () => {
      const jwt = new JWT({
        email: 'foo@serviceaccount.com',
        key: fs.readFileSync(PEM_PATH, 'utf8'),
        scopes: [],
        subject: 'bar@subjectaccount.com',
      });
      const headers = await jwt.getRequestHeaders();
      assert.deepStrictEqual(headers, {});
    });
  });
});
