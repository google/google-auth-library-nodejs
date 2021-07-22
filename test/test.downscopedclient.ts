// Copyright 2021 Google LLC
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
import {describe, it, before, after, beforeEach, afterEach} from 'mocha';
import * as nock from 'nock';
import * as sinon from 'sinon';

import {StsSuccessfulResponse} from '../src/auth/stscredentials';
import {DownscopedClient} from '../src/auth/downscopedclient';
import {AuthClient} from '../src/auth/authclient';
import {mockStsBetaTokenExchange} from './externalclienthelper';
import {GoogleAuth} from '../src';

nock.disableNetConnect();

interface SampleResponse {
  foo: string;
  bar: number;
}

describe('DownscopedClient', () => {
  let clock: sinon.SinonFakeTimers;

  const auth = new GoogleAuth({
    keyFilename: './test/fixtures/private.json',
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });
  let client: AuthClient;

  const ONE_HOUR_IN_SECS = 3600;
  const testAvailableResource =
    '//storage.googleapis.com/projects/_/buckets/bucket-123';
  const testAvailablePermission1 = 'inRole:roles/storage.objectViewer';
  const testAvailablePermission2 = 'inRole:roles/storage.objectAdmin';
  const testAvailabilityConditionExpression =
    "resource.name.startsWith('projects/_/buckets/bucket-123/objects/prefix')";
  const testAvailabilityConditionTitle = 'Test availability condition title.';
  const testAvailabilityConditionDescription =
    'Test availability condition description.';
  const testClientAccessBoundary = {
    accessBoundary: {
      accessBoundaryRules: [
        {
          availableResource: testAvailableResource,
          availablePermissions: [testAvailablePermission1],
          availabilityCondition: {
            expression: testAvailabilityConditionExpression,
          },
        },
      ],
    },
  };
  const stsSuccessfulResponse: StsSuccessfulResponse = {
    access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN_0',
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: ONE_HOUR_IN_SECS,
    scope: 'scope1 scope2',
  };
  /**
   * Offset to take into account network delays and server clock skews.
   */
  const EXPIRATION_TIME_OFFSET = 5 * 60 * 1000;

  beforeEach(async () => {
    client = await auth.getClient();
  });

  afterEach(() => {
    nock.cleanAll();
    if (clock) {
      clock.restore();
    }
  });

  describe('Constructor', () => {
    it('should throw on empty access boundary rule', () => {
      const expectedError = new Error(
        'At least one access boundary rule needs to be defined.'
      );
      const cabWithEmptyAccessBoundaryRules = {
        accessBoundary: {
          accessBoundaryRules: [],
        },
      };
      assert.throws(() => {
        return new DownscopedClient(client, cabWithEmptyAccessBoundaryRules);
      }, expectedError);
    });

    it('should throw on exceed number of access boundary rules', () => {
      const expectedError = new Error(
        'Access boundary rule exceeds limit, max 10 allowed.'
      );
      const cabWithExceedingAccessBoundaryRules = {
        accessBoundary: {
          accessBoundaryRules: [] as any,
        },
      };
      const testAccessBoundaryRule = {
        availableResource: testAvailableResource,
        availablePermissions: [testAvailablePermission1],
        availabilityCondition: {
          expression: testAvailabilityConditionExpression,
        },
      };
      for (let num = 0; num <= 10; num++) {
        cabWithExceedingAccessBoundaryRules.accessBoundary.accessBoundaryRules.push(
          testAccessBoundaryRule
        );
      }
      assert.throws(() => {
        return new DownscopedClient(
          client,
          cabWithExceedingAccessBoundaryRules
        );
      }, expectedError);
    });

    it('should throw on no permissions are defined in access boundary rules', () => {
      const expectedError = new Error(
        'At least one permission should be defined in access boundary rules.'
      );
      const cabWithNoPermissionIncluded = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.throws(() => {
        return new DownscopedClient(client, cabWithNoPermissionIncluded);
      }, expectedError);
    });

    it('should not throw on one access boundary rule with all fields included', () => {
      const cabWithOneAccessBoundaryRule = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithOneAccessBoundaryRule);
      });
    });

    it('should not throw with multiple permissions defined', () => {
      const cabWithTwoAvailblePermissions = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [
                testAvailablePermission1,
                testAvailablePermission2,
              ],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
                title: testAvailabilityConditionTitle,
                description: testAvailabilityConditionDescription,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithTwoAvailblePermissions);
      });
    });

    it('should not throw with empty available condition', () => {
      const cabWithNoAvailabilityCondition = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(client, cabWithNoAvailabilityCondition);
      });
    });

    it('should not throw with only expression setup in available condition', () => {
      const cabWithOnlyAvailabilityConditionExpression = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [
                testAvailablePermission1,
                testAvailablePermission2,
              ],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      assert.doesNotThrow(() => {
        return new DownscopedClient(
          client,
          cabWithOnlyAvailabilityConditionExpression
        );
      });
    });

    it('should set custom RefreshOptions', () => {
      const refreshOptions = {
        eagerRefreshThresholdMillis: 5000,
        forceRefreshOnFailure: true,
      };
      const cabWithOneAccessBoundaryRules = {
        accessBoundary: {
          accessBoundaryRules: [
            {
              availableResource: testAvailableResource,
              availablePermissions: [testAvailablePermission1],
              availabilityCondition: {
                expression: testAvailabilityConditionExpression,
              },
            },
          ],
        },
      };
      const downscopedClient = new DownscopedClient(
        client,
        cabWithOneAccessBoundaryRules,
        refreshOptions
      );
      assert.strictEqual(
        downscopedClient.forceRefreshOnFailure,
        refreshOptions.forceRefreshOnFailure
      );
      assert.strictEqual(
        downscopedClient.eagerRefreshThresholdMillis,
        refreshOptions.eagerRefreshThresholdMillis
      );
    });
  });

  describe('getAccessToken()', () => {
    let sandbox: sinon.SinonSandbox;
    before(() => {
      const expectedAccessTokenResponse = {
        token: 'subject_token',
      };
      sandbox = sinon.createSandbox();
      sandbox
        .stub(client, 'getAccessToken')
        .resolves(expectedAccessTokenResponse);
    });

    after(() => {
      sandbox.restore();
    });

    it('should return current unexpired cached DownscopedClient access token', async () => {
      const now = new Date().getTime();
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      downscopedClient.setCredentials(credentials);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);
    });

    it('should refresh a new DownscopedClient access when cached one gets expired', async () => {
      const now = new Date().getTime();
      clock = sinon.useFakeTimers(now);
      const credentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const scope = mockStsBetaTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options:
              testClientAccessBoundary &&
              JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);

      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      downscopedClient.setCredentials(credentials);

      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(tokenResponse.token, credentials.access_token);

      clock.tick(1);
      const refreshedTokenResponse = await downscopedClient.getAccessToken();

      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        stsSuccessfulResponse.access_token
      );
      scope.done();
    });

    it('should return new DownscopedClient access token when there is no cached downscoped access token', async () => {
      const scope = mockStsBetaTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponse,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options:
              testClientAccessBoundary &&
              JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);

      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      const tokenResponse = await downscopedClient.getAccessToken();

      assert.deepStrictEqual(
        tokenResponse.token,
        stsSuccessfulResponse.access_token
      );
      scope.done();
    });

    it('should copy source cred expiry time if STS response does not return expiry time', async () => {
      const now = new Date().getTime();
      clock = sinon.useFakeTimers(now);
      const sourceCredentials = client.credentials;
      const downscopedCredentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const stsSuccessfulResponseWithoutExpireInField = Object.assign(
        stsSuccessfulResponse,
        {}
      );
      delete stsSuccessfulResponseWithoutExpireInField.expires_in;
      const scope = mockStsBetaTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponseWithoutExpireInField,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options:
              testClientAccessBoundary &&
              JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);
      client.setCredentials(sourceCredentials);
      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      assert.strictEqual(client.credentials.expiry_date, 1);
      downscopedClient.setCredentials(downscopedCredentials);

      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        tokenResponse.token,
        downscopedCredentials.access_token
      );

      clock.tick(1);
      const refreshedTokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        stsSuccessfulResponseWithoutExpireInField.access_token
      );
      assert.strictEqual(
        downscopedClient.credentials.expiry_date,
        sourceCredentials.expiry_date
      );
      scope.done();
    });

    it('should has no expiry date if source cred has no expiry time and STS response does not return one', async () => {
      const now = new Date().getTime();
      clock = sinon.useFakeTimers(now);
      const downscopedCredentials = {
        access_token: 'DOWNSCOPED_CLIENT_ACCESS_TOKEN',
        expiry_date: now + ONE_HOUR_IN_SECS * 1000,
      };
      const credentials = {
        access_token: 'ACCESS_TOKEN',
      };
      const stsSuccessfulResponseWithoutExpireInField = Object.assign(
        stsSuccessfulResponse,
        {}
      );
      delete stsSuccessfulResponseWithoutExpireInField.expires_in;
      const scope = mockStsBetaTokenExchange([
        {
          statusCode: 200,
          response: stsSuccessfulResponseWithoutExpireInField,
          request: {
            grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
            requested_token_type:
              'urn:ietf:params:oauth:token-type:access_token',
            subject_token: 'subject_token',
            subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
            options:
              testClientAccessBoundary &&
              JSON.stringify(testClientAccessBoundary),
          },
        },
      ]);

      assert.strictEqual(client.credentials.expiry_date, 1);
      client.setCredentials(credentials);
      assert.strictEqual(client.credentials.expiry_date, undefined);

      const downscopedClient = new DownscopedClient(
        client,
        testClientAccessBoundary
      );
      downscopedClient.setCredentials(downscopedCredentials);

      clock.tick(ONE_HOUR_IN_SECS * 1000 - EXPIRATION_TIME_OFFSET - 1);
      const tokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        tokenResponse.token,
        downscopedCredentials.access_token
      );

      clock.tick(1);
      const refreshedTokenResponse = await downscopedClient.getAccessToken();
      assert.deepStrictEqual(
        refreshedTokenResponse.token,
        stsSuccessfulResponseWithoutExpireInField.access_token
      );
      assert.strictEqual(
        downscopedClient.credentials.access_token,
        stsSuccessfulResponseWithoutExpireInField.access_token
      );
      assert.strictEqual(downscopedClient.credentials.expiry_date, null);
      scope.done();
    });
  });

  describe('getRequestHeader()', () => {
    it('should return unimplemented error when calling getRequestHeader()', async () => {
      const expectedError = new Error('Not implemented.');
      const cabClient = new DownscopedClient(client, testClientAccessBoundary);
      await assert.rejects(cabClient.getRequestHeaders(), expectedError);
    });
  });

  describe('request()', () => {
    it('should return unimplemented error when request with opts', () => {
      const cabClient = new DownscopedClient(client, testClientAccessBoundary);
      const exampleRequest = {
        key1: 'value1',
        key2: 'value2',
      };
      const expectedError = new Error('Not implemented.');

      assert.throws(() => {
        return cabClient.request<SampleResponse>({
          url: 'https://example.com/api',
          method: 'POST',
          data: exampleRequest,
          responseType: 'json',
        });
      }, expectedError);
    });
  });
});
