/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as assert from 'assert';
import * as nock from 'nock';
import {describe, it, afterEach} from 'mocha';
import {Impersonated, JWT} from '../src';
import {CredentialRequest} from '../src/auth/credentials';

const PEM_PATH = './test/fixtures/private.pem';

nock.disableNetConnect();

const url = 'http://example.com';

function createGTokenMock(body: CredentialRequest) {
  return nock('https://www.googleapis.com')
    .post('/oauth2/v4/token')
    .reply(200, body);
}

interface ImpersonatedCredentialRequest {
  delegates: string[];
  scope: string[];
  lifetime: string;
}

describe('impersonated', () => {
  afterEach(() => {
    nock.cleanAll();
  });
  it('should request impersonated credentials on first request', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      nock(url).get('/').reply(200),
      createGTokenMock({
        access_token: 'abc123',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken',
          (body: ImpersonatedCredentialRequest) => {
            assert.strictEqual(body.lifetime, '30s');
            assert.deepStrictEqual(body.delegates, []);
            assert.deepStrictEqual(body.scope, [
              'https://www.googleapis.com/auth/cloud-platform',
            ]);
            return true;
          }
        )
        .reply(200, {
          accessToken: 'qwerty345',
          expiryDate: tomorrow.toISOString(),
        }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    await impersonated.request({url});
    assert.strictEqual(impersonated.credentials.access_token, 'qwerty345');
    scopes.forEach(s => s.done());
  });
  it('should not request impersonated credentials on second request', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      nock(url).get('/').reply(200),
      nock(url).get('/').reply(200),
      createGTokenMock({
        access_token: 'abc123',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken',
          (body: ImpersonatedCredentialRequest) => {
            assert.strictEqual(body.lifetime, '30s');
            assert.deepStrictEqual(body.delegates, []);
            assert.deepStrictEqual(body.scope, [
              'https://www.googleapis.com/auth/cloud-platform',
            ]);
            return true;
          }
        )
        .reply(200, {
          accessToken: 'qwerty345',
          expiryDate: tomorrow.toISOString(),
        }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    await impersonated.request({url});
    await impersonated.request({url});
    assert.strictEqual(impersonated.credentials.access_token, 'qwerty345');
    scopes.forEach(s => s.done());
  });
  it('should request impersonated credentials once new credentials expire', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      nock(url).get('/').reply(200),
      nock(url).get('/').reply(200),
      createGTokenMock({
        access_token: 'abc123',
      }),
      createGTokenMock({
        access_token: 'abc456',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken',
          () => {
            return true;
          }
        )
        .reply(200, {
          accessToken: 'qwerty345',
          expiryDate: tomorrow.toISOString(),
        }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken',
          () => {
            return true;
          }
        )
        .reply(200, {
          accessToken: 'qwerty456',
          expiryDate: tomorrow.toISOString(),
        }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    await impersonated.request({url});
    // Force both the wrapped and impersonated client to appear to have
    // expired:
    jwt.credentials.expiry_date = Date.now();
    impersonated.credentials.expiry_date = Date.now();
    await impersonated.request({url});
    assert.strictEqual(impersonated.credentials.access_token, 'qwerty456');
    scopes.forEach(s => s.done());
  });
  it('throws meaningful error when context available', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      createGTokenMock({
        access_token: 'abc123',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken'
        )
        .reply(404, {
          error: {
            code: 404,
            message: 'Requested entity was not found.',
            status: 'NOT_FOUND',
          },
        }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    impersonated.credentials.access_token = 'initial-access-token';
    impersonated.credentials.expiry_date = Date.now() - 10000;
    await assert.rejects(impersonated.request({url}), /NOT_FOUND/);
    scopes.forEach(s => s.done());
  });
  it('handles errors without context', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      createGTokenMock({
        access_token: 'abc123',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken'
        )
        .reply(500),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    impersonated.credentials.access_token = 'initial-access-token';
    impersonated.credentials.expiry_date = Date.now() - 10000;
    await assert.rejects(impersonated.request({url}), /unable to impersonate/);
    scopes.forEach(s => s.done());
  });
  it('should populate request headers', async () => {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const scopes = [
      createGTokenMock({
        access_token: 'abc123',
      }),
      nock('https://iamcredentials.googleapis.com')
        .post(
          '/v1/projects/-/serviceAccounts/target@project.iam.gserviceaccount.com:generateAccessToken',
          (body: ImpersonatedCredentialRequest) => {
            assert.strictEqual(body.lifetime, '30s');
            assert.deepStrictEqual(body.delegates, []);
            assert.deepStrictEqual(body.scope, [
              'https://www.googleapis.com/auth/cloud-platform',
            ]);
            return true;
          }
        )
        .reply(200, {
          accessToken: 'qwerty345',
          expiryDate: tomorrow.toISOString(),
        }),
    ];
    const jwt = new JWT(
      'foo@serviceaccount.com',
      PEM_PATH,
      undefined,
      ['http://bar', 'http://foo'],
      'bar@subjectaccount.com'
    );
    const impersonated = new Impersonated({
      sourceClient: jwt,
      targetPrincipal: 'target@project.iam.gserviceaccount.com',
      lifetime: 30,
      delegates: [],
      targetScopes: ['https://www.googleapis.com/auth/cloud-platform'],
    });
    impersonated.credentials.access_token = 'initial-access-token';
    impersonated.credentials.expiry_date = Date.now() - 10000;
    const headers = await impersonated.getRequestHeaders();
    assert.strictEqual(headers['Authorization'], 'Bearer qwerty345');
    scopes.forEach(s => s.done());
  });
});
