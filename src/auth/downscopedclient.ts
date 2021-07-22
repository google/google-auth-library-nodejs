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

import {GaxiosOptions, GaxiosPromise, GaxiosResponse} from 'gaxios';

import {BodyResponseCallback} from '../transporters';
import {Credentials} from './credentials';
import {AuthClient} from './authclient';

import {GetAccessTokenResponse, Headers, RefreshOptions} from './oauth2client';
import * as sts from './stscredentials';

/**
 * The required token exchange grant_type: rfc8693#section-2.1
 */
const STS_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
/**
 * The requested token exchange requested_token_type: rfc8693#section-2.1
 */
const STS_REQUEST_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
/**
 * The requested token exchange subject_token_type: rfc8693#section-2.1
 */
const STS_SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
/** The STS access token exchange end point. */
const STS_ACCESS_TOKEN_URL = 'https://sts.googleapis.com/v1beta/token';

/**
 * Offset to take into account network delays and server clock skews.
 */
export const EXPIRATION_TIME_OFFSET = 5 * 60 * 1000;

/**
 * Internal interface for tracking the access token expiration time.
 */
interface CredentialsWithResponse extends Credentials {
  res?: GaxiosResponse | null;
}

/**
 * Defines an upper bound of permissions available for a GCP credential.
 */
interface CredentialAccessBoundary {
  accessBoundary: {
    accessBoundaryRules: AccessBoundaryRule[];
  };
}

/** Defines an upper bound of permissions on a particular resource. */
interface AccessBoundaryRule {
  availablePermissions: string[];
  availableResource: string;
  availabilityCondition?: AvailabilityCondition;
}

/**
 * An optional condition that can be used as part of a
 * CredentialAccessBoundary to further restrict permissions.
 */
interface AvailabilityCondition {
  expression: string;
  title?: string;
  description?: string;
}

export class DownscopedClient extends AuthClient {
  /**
   * OAuth scopes for the GCP access token to use. When not provided,
   * the default https://www.googleapis.com/auth/cloud-platform is
   * used.
   */
  private cachedDownscopedAccessToken: CredentialsWithResponse | null;
  private readonly stsCredential: sts.StsCredentials;
  public readonly authClient: AuthClient;
  public readonly credentialAccessBoundary: CredentialAccessBoundary;
  public readonly eagerRefreshThresholdMillis: number;
  public readonly forceRefreshOnFailure: boolean;

  constructor(
    private client: AuthClient,
    private cab: CredentialAccessBoundary,
    additionalOptions?: RefreshOptions
  ) {
    super();

    // Check a number of 1-10 access boundary rules are defined within credential access boundary.
    if (cab.accessBoundary.accessBoundaryRules.length === 0) {
      throw new Error('At least one access boundary rule needs to be defined.');
    } else if (cab.accessBoundary.accessBoundaryRules.length > 10) {
      throw new Error('Access boundary rule exceeds limit, max 10 allowed.');
    }

    // Check at least one permission should be defined in each access boundary rule.
    for (const rule of cab.accessBoundary.accessBoundaryRules) {
      if (rule.availablePermissions.length === 0) {
        throw new Error(
          'At least one permission should be defined in access boundary rules.'
        );
      }
    }

    this.stsCredential = new sts.StsCredentials(STS_ACCESS_TOKEN_URL);
    // Default OAuth scope. This could be overridden via public property.
    this.cachedDownscopedAccessToken = null;
    this.credentialAccessBoundary = cab;
    this.authClient = client;
    // As threshold could be zero,
    // eagerRefreshThresholdMillis || EXPIRATION_TIME_OFFSET will override the
    // zero value.
    if (typeof additionalOptions?.eagerRefreshThresholdMillis !== 'number') {
      this.eagerRefreshThresholdMillis = EXPIRATION_TIME_OFFSET;
    } else {
      this.eagerRefreshThresholdMillis = additionalOptions!
        .eagerRefreshThresholdMillis as number;
    }
    this.forceRefreshOnFailure = !!additionalOptions?.forceRefreshOnFailure;
  }

  /**
   * Provides a mechanism to inject Downscoped access tokens directly.
   * When the provided credential expires, a new credential, using the
   * external account options are retrieved.
   * Notice DownscopedClient is the broker class mainly used for generate
   * downscoped access tokens, it is unlikely we call this function in real
   * use case.
   * We implement to make this a helper function for testing all cases in getAccessToken().
   * @param credentials The Credentials object to set on the current client.
   */
  setCredentials(credentials: Credentials) {
    super.setCredentials(credentials);
    this.cachedDownscopedAccessToken = credentials;
  }

  async getAccessToken(): Promise<GetAccessTokenResponse> {
    // If the cached access token is unavailable or expired, force refresh.
    // The Downscoped access token will be returned in GetAccessTokenResponse format.
    // If cached access token is unavailable or expired, force refresh.
    if (
      !this.cachedDownscopedAccessToken ||
      this.isExpired(this.cachedDownscopedAccessToken)
    ) {
      await this.refreshAccessTokenAsync();
    }
    // Return Downscoped access token in GetAccessTokenResponse format.
    return {
      token: this.cachedDownscopedAccessToken!.access_token,
      res: this.cachedDownscopedAccessToken!.res,
    };
  }

  /**
   * The main authentication interface. It takes an optional url which when
   * present is the endpoint> being accessed, and returns a Promise which
   * resolves with authorization header fields.
   *
   * The result has the form:
   * { Authorization: 'Bearer <access_token_value>' }
   */
  async getRequestHeaders(): Promise<Headers> {
    throw new Error('Not implemented.');
  }

  /**
   * Provides a request implementation with OAuth 2.0 flow. In cases of
   * HTTP 401 and 403 responses, it automatically asks for a new access token
   * and replays the unsuccessful request.
   * @param opts Request options.
   * @param callback callback.
   * @return A promise that resolves with the HTTP response when no callback
   * is provided.
   */
  request<T>(opts: GaxiosOptions): GaxiosPromise<T>;
  request<T>(opts: GaxiosOptions, callback: BodyResponseCallback<T>): void;
  request<T>(
    opts: GaxiosOptions,
    callback?: BodyResponseCallback<T>
  ): GaxiosPromise<T> | void {
    throw new Error('Not implemented.');
  }

  /**
   * Forces token refresh, even if unexpired tokens are currently cached.
   * GCP access tokens are retrieved from authclient object/source credential.
   * Thenm GCP access tokens are exchanged for downscoped access tokens via the
   * token exchange endpoint.
   * @return A promise that resolves with the fresh downscoped access token.
   */
  protected async refreshAccessTokenAsync(): Promise<CredentialsWithResponse> {
    // Retrieve GCP access token from source credential.
    const subjectToken = await (await this.authClient.getAccessToken()).token;
    // Construct the STS credentials options.
    const stsCredentialsOptions: sts.StsCredentialsOptions = {
      grantType: STS_GRANT_TYPE,
      requestedTokenType: STS_REQUEST_TOKEN_TYPE,
      subjectToken: subjectToken as string,
      subjectTokenType: STS_SUBJECT_TOKEN_TYPE,
    };

    // Exchange the source access token for a Downscoped access token.
    const stsResponse = await this.stsCredential.exchangeToken(
      stsCredentialsOptions,
      undefined,
      this.credentialAccessBoundary
    );

    const sourceCredExpireDate =
      this.authClient.credentials?.expiry_date || null;
    const expiryDate = stsResponse.expires_in
      ? new Date().getTime() + stsResponse.expires_in * 1000
      : sourceCredExpireDate;
    // Save response in cached access token.
    this.cachedDownscopedAccessToken = {
      access_token: stsResponse.access_token,
      expiry_date: expiryDate,
      res: stsResponse.res,
    };

    // Save credentials.
    this.credentials = {};
    Object.assign(this.credentials, this.cachedDownscopedAccessToken);
    delete (this.credentials as CredentialsWithResponse).res;

    // Trigger tokens event to notify external listeners.
    this.emit('tokens', {
      refresh_token: null,
      expiry_date: this.cachedDownscopedAccessToken!.expiry_date,
      access_token: this.cachedDownscopedAccessToken!.access_token,
      token_type: 'Bearer',
      id_token: null,
    });
    // Return the cached access token.
    return this.cachedDownscopedAccessToken;
  }

  /**
   * Returns whether the provided credentials are expired or not.
   * If there is no expiry time, assumes the token is not expired or expiring.
   * @param downscopedAccessToken The credentials to check for expiration.
   * @return Whether the credentials are expired or not.
   */
  private isExpired(downscopedAccessToken: Credentials): boolean {
    const now = new Date().getTime();
    return downscopedAccessToken.expiry_date
      ? now >=
          downscopedAccessToken.expiry_date - this.eagerRefreshThresholdMillis
      : false;
  }
}
