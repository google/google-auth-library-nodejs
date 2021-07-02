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

import {
  GaxiosError,
  GaxiosOptions,
  GaxiosPromise,
  GaxiosResponse,
} from 'gaxios';
import * as stream from 'stream';

import {Credentials} from './credentials';
import {AuthClient} from './authclient';
import {BodyResponseCallback} from '../transporters';
import {GetAccessTokenResponse, Headers, RefreshOptions} from './oauth2client';
import * as sts from './stscredentials';
import {ClientAuthentication} from './oauth2common';

/**
 * The required token exchange grant_type: rfc8693#section-2.1
 */
const STS_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';
/**
 * The requested token exchange requested_token_type: rfc8693#section-2.1
 */
const STS_REQUEST_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
/** The default OAuth scope to request when none is provided. */
const DEFAULT_OAUTH_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
/**
 * Offset to take into account network delays and server clock skews.
 */
export const EXPIRATION_TIME_OFFSET = 5 * 60 * 1000;
/**
 * The credentials JSON file type for external account clients.
 * There are 3 types of JSON configs:
 * 1. authorized_user => Google end user credential
 * 2. service_account => Google service account credential
 * 3. external_Account => non-GCP service (eg. AWS, Azure, K8s)
 */
export const EXTERNAL_ACCOUNT_TYPE = 'external_account';
/** Cloud resource manager URL used to retrieve project information. */
export const CLOUD_RESOURCE_MANAGER =
  'https://cloudresourcemanager.googleapis.com/v1/projects/';

/**
 * Base external account credentials json interface.
 */
export interface BaseExternalAccountClientOptions {
  type: string;
  audience: string;
  subject_token_type: string;
  service_account_impersonation_url?: string;
  token_url: string;
  token_info_url?: string;
  client_id?: string;
  client_secret?: string;
  quota_project_id?: string;
}

/**
 * Interface defining the successful response for iamcredentials
 * generateAccessToken API.
 * https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
 */
export interface IamGenerateAccessTokenResponse {
  accessToken: string;
  // ISO format used for expiration time: 2014-10-02T15:01:23.045123456Z
  expireTime: string;
}

/**
 * Interface defining the project information response returned by the cloud
 * resource manager.
 * https://cloud.google.com/resource-manager/reference/rest/v1/projects#Project
 */
export interface ProjectInfo {
  projectNumber: string;
  projectId: string;
  lifecycleState: string;
  name: string;
  createTime?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  parent: {[key: string]: any};
}

/**
 * Internal interface for tracking the access token expiration time.
 */
interface CredentialsWithResponse extends Credentials {
  res?: GaxiosResponse | null;
}

/**
 * Base external account client. This is used to instantiate AuthClients for
 * exchanging external account credentials for GCP access token and authorizing
 * requests to GCP APIs.
 * The base class implements common logic for exchanging various type of
 * external credentials for GCP access token. The logic of determining and
 * retrieving the external credential based on the environment and
 * credential_source will be left for the subclasses.
 */
export abstract class BaseExternalAccountClient extends AuthClient {
  /**
   * OAuth scopes for the GCP access token to use. When not provided,
   * the default https://www.googleapis.com/auth/cloud-platform is
   * used.
   */
  public scopes?: string | string[];
  private cachedAccessToken: CredentialsWithResponse | null;
  protected readonly audience: string;
  private readonly subjectTokenType: string;
  private readonly serviceAccountImpersonationUrl?: string;
  private readonly stsCredential: sts.StsCredentials;
  public projectId: string | null;
  public projectNumber: string | null;
  public readonly eagerRefreshThresholdMillis: number;
  public readonly forceRefreshOnFailure: boolean;
  public useJWTAccessAlways?: boolean;
  public defaultServicePath?: string;

  /**
   * Instantiate a BaseExternalAccountClient instance using the provided JSON
   * object loaded from an external account credentials file.
   * @param options The external account options object typically loaded
   *   from the external account JSON credential file.
   * @param additionalOptions Optional additional behavior customization
   *   options. These currently customize expiration threshold time and
   *   whether to retry on 401/403 API request errors.
   */
  constructor(
    options: BaseExternalAccountClientOptions,
    additionalOptions?: RefreshOptions
  ) {
    super();
    if (options.type !== EXTERNAL_ACCOUNT_TYPE) {
      throw new Error(
        `Expected "${EXTERNAL_ACCOUNT_TYPE}" type but ` +
          `received "${options.type}"`
      );
    }
    const clientAuth = options.client_id
      ? ({
          confidentialClientType: 'basic',
          clientId: options.client_id,
          clientSecret: options.client_secret,
        } as ClientAuthentication)
      : undefined;
    this.stsCredential = new sts.StsCredentials(options.token_url, clientAuth);
    // Default OAuth scope. This could be overridden via public property.
    this.scopes = [DEFAULT_OAUTH_SCOPE];
    this.cachedAccessToken = null;
    this.audience = options.audience;
    this.subjectTokenType = options.subject_token_type;
    this.quotaProjectId = options.quota_project_id;
    this.serviceAccountImpersonationUrl =
      options.service_account_impersonation_url;
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
    this.projectId = null;
    this.projectNumber = this.getProjectNumber(this.audience);
  }

  /**
   * Provides a mechanism to inject GCP access tokens directly.
   * When the provided credential expires, a new credential, using the
   * external account options, is retrieved.
   * @param credentials The Credentials object to set on the current client.
   */
  setCredentials(credentials: Credentials) {
    super.setCredentials(credentials);
    this.cachedAccessToken = credentials;
  }

  /**
   * Triggered when a external subject token is needed to be exchanged for a GCP
   * access token via GCP STS endpoint.
   * This abstract method needs to be implemented by subclasses depending on
   * the type of external credential used.
   * @return A promise that resolves with the external subject token.
   */
  abstract async retrieveSubjectToken(): Promise<string>;

  /**
   * @return A promise that resolves with the current GCP access token
   *   response. If the current credential is expired, a new one is retrieved.
   */
  async getAccessToken(): Promise<GetAccessTokenResponse> {
    // If cached access token is unavailable or expired, force refresh.
    if (!this.cachedAccessToken || this.isExpired(this.cachedAccessToken)) {
      await this.refreshAccessTokenAsync();
    }
    // Return GCP access token in GetAccessTokenResponse format.
    return {
      token: this.cachedAccessToken!.access_token,
      res: this.cachedAccessToken!.res,
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
    const accessTokenResponse = await this.getAccessToken();
    const headers: Headers = {
      Authorization: `Bearer ${accessTokenResponse.token}`,
    };
    return this.addSharedMetadataHeaders(headers);
  }

  /**
   * Provides a request implementation with OAuth 2.0 flow. In cases of
   * HTTP 401 and 403 responses, it automatically asks for a new access token
   * and replays the unsuccessful request.
   * @param opts Request options.
   * @param callback callback.
   * @return A promise that resolves with the HTTP response when no callback is
   *   provided.
   */
  request<T>(opts: GaxiosOptions): GaxiosPromise<T>;
  request<T>(opts: GaxiosOptions, callback: BodyResponseCallback<T>): void;
  request<T>(
    opts: GaxiosOptions,
    callback?: BodyResponseCallback<T>
  ): GaxiosPromise<T> | void {
    if (callback) {
      this.requestAsync<T>(opts).then(
        r => callback(null, r),
        e => {
          return callback(e, e.response);
        }
      );
    } else {
      return this.requestAsync<T>(opts);
    }
  }

  /**
   * @return A promise that resolves with the project ID corresponding to the
   *   current workload identity pool. When not determinable, this resolves with
   *   null.
   *   This is introduced to match the current pattern of using the Auth
   *   library:
   *   const projectId = await auth.getProjectId();
   *   const url = `https://dns.googleapis.com/dns/v1/projects/${projectId}`;
   *   const res = await client.request({ url });
   *   The resource may not have permission
   *   (resourcemanager.projects.get) to call this API or the required
   *   scopes may not be selected:
   *   https://cloud.google.com/resource-manager/reference/rest/v1/projects/get#authorization-scopes
   */
  async getProjectId(): Promise<string | null> {
    if (this.projectId) {
      // Return previously determined project ID.
      return this.projectId;
    } else if (this.projectNumber) {
      // Preferable not to use request() to avoid retrial policies.
      const headers = await this.getRequestHeaders();
      const response = await this.transporter.request<ProjectInfo>({
        headers,
        url: `${CLOUD_RESOURCE_MANAGER}${this.projectNumber}`,
        responseType: 'json',
      });
      this.projectId = response.data.projectId;
      return this.projectId;
    }
    return null;
  }

  /**
   * Authenticates the provided HTTP request, processes it and resolves with the
   * returned response.
   * @param opts The HTTP request options.
   * @param retry Whether the current attempt is a retry after a failed attempt.
   * @return A promise that resolves with the successful response.
   */
  protected async requestAsync<T>(
    opts: GaxiosOptions,
    retry = false
  ): Promise<GaxiosResponse<T>> {
    let response: GaxiosResponse;
    try {
      const requestHeaders = await this.getRequestHeaders();
      opts.headers = opts.headers || {};
      if (requestHeaders && requestHeaders['x-goog-user-project']) {
        opts.headers['x-goog-user-project'] =
          requestHeaders['x-goog-user-project'];
      }
      if (requestHeaders && requestHeaders.Authorization) {
        opts.headers.Authorization = requestHeaders.Authorization;
      }
      response = await this.transporter.request<T>(opts);
    } catch (e) {
      const res = (e as GaxiosError).response;
      if (res) {
        const statusCode = res.status;
        // Retry the request for metadata if the following criteria are true:
        // - We haven't already retried.  It only makes sense to retry once.
        // - The response was a 401 or a 403
        // - The request didn't send a readableStream
        // - forceRefreshOnFailure is true
        const isReadableStream = res.config.data instanceof stream.Readable;
        const isAuthErr = statusCode === 401 || statusCode === 403;
        if (
          !retry &&
          isAuthErr &&
          !isReadableStream &&
          this.forceRefreshOnFailure
        ) {
          await this.refreshAccessTokenAsync();
          return await this.requestAsync<T>(opts, true);
        }
      }
      throw e;
    }
    return response;
  }

  /**
   * Forces token refresh, even if unexpired tokens are currently cached.
   * External credentials are exchanged for GCP access tokens via the token
   * exchange endpoint and other settings provided in the client options
   * object.
   * If the service_account_impersonation_url is provided, an additional
   * step to exchange the external account GCP access token for a service
   * account impersonated token is performed.
   * @return A promise that resolves with the fresh GCP access tokens.
   */
  protected async refreshAccessTokenAsync(): Promise<CredentialsWithResponse> {
    // Retrieve the external credential.
    const subjectToken = await this.retrieveSubjectToken();
    // Construct the STS credentials options.
    const stsCredentialsOptions: sts.StsCredentialsOptions = {
      grantType: STS_GRANT_TYPE,
      audience: this.audience,
      requestedTokenType: STS_REQUEST_TOKEN_TYPE,
      subjectToken,
      subjectTokenType: this.subjectTokenType,
      // generateAccessToken requires the provided access token to have
      // scopes:
      // https://www.googleapis.com/auth/iam or
      // https://www.googleapis.com/auth/cloud-platform
      // The new service account access token scopes will match the user
      // provided ones.
      scope: this.serviceAccountImpersonationUrl
        ? [DEFAULT_OAUTH_SCOPE]
        : this.getScopesArray(),
    };

    // Exchange the external credentials for a GCP access token.
    const stsResponse = await this.stsCredential.exchangeToken(
      stsCredentialsOptions
    );

    if (this.serviceAccountImpersonationUrl) {
      this.cachedAccessToken = await this.getImpersonatedAccessToken(
        stsResponse.access_token
      );
    } else {
      // Save response in cached access token.
      this.cachedAccessToken = {
        access_token: stsResponse.access_token,
        expiry_date: new Date().getTime() + stsResponse.expires_in * 1000,
        res: stsResponse.res,
      };
    }

    // Save credentials.
    this.credentials = {};
    Object.assign(this.credentials, this.cachedAccessToken);
    delete (this.credentials as CredentialsWithResponse).res;

    // Trigger tokens event to notify external listeners.
    this.emit('tokens', {
      refresh_token: null,
      expiry_date: this.cachedAccessToken!.expiry_date,
      access_token: this.cachedAccessToken!.access_token,
      token_type: 'Bearer',
      id_token: null,
    });
    // Return the cached access token.
    return this.cachedAccessToken;
  }

  /**
   * Returns the workload identity pool project number if it is determinable
   * from the audience resource name.
   * @param audience The STS audience used to determine the project number.
   * @return The project number associated with the workload identity pool, if
   *   this can be determined from the STS audience field. Otherwise, null is
   *   returned.
   */
  private getProjectNumber(audience: string): string | null {
    // STS audience pattern:
    // //iam.googleapis.com/projects/$PROJECT_NUMBER/locations/...
    const match = audience.match(/\/projects\/([^/]+)/);
    if (!match) {
      return null;
    }
    return match[1];
  }

  /**
   * Exchanges an external account GCP access token for a service
   * account impersonated access token using iamcredentials
   * GenerateAccessToken API.
   * @param token The access token to exchange for a service account access
   *   token.
   * @return A promise that resolves with the service account impersonated
   *   credentials response.
   */
  private async getImpersonatedAccessToken(
    token: string
  ): Promise<CredentialsWithResponse> {
    const opts: GaxiosOptions = {
      url: this.serviceAccountImpersonationUrl!,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      data: {
        scope: this.getScopesArray(),
      },
      responseType: 'json',
    };
    const response =
      await this.transporter.request<IamGenerateAccessTokenResponse>(opts);
    const successResponse = response.data;
    return {
      access_token: successResponse.accessToken,
      // Convert from ISO format to timestamp.
      expiry_date: new Date(successResponse.expireTime).getTime(),
      res: response,
    };
  }

  /**
   * Returns whether the provided credentials are expired or not.
   * If there is no expiry time, assumes the token is not expired or expiring.
   * @param accessToken The credentials to check for expiration.
   * @return Whether the credentials are expired or not.
   */
  private isExpired(accessToken: Credentials): boolean {
    const now = new Date().getTime();
    return accessToken.expiry_date
      ? now >= accessToken.expiry_date - this.eagerRefreshThresholdMillis
      : false;
  }

  /**
   * @return The list of scopes for the requested GCP access token.
   */
  private getScopesArray(): string[] {
    // Since scopes can be provided as string or array, the type should
    // be normalized.
    if (typeof this.scopes === 'string') {
      return [this.scopes];
    } else if (typeof this.scopes === 'undefined') {
      return [DEFAULT_OAUTH_SCOPE];
    } else {
      return this.scopes;
    }
  }
}
