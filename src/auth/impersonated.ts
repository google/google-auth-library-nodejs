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

import {GetTokenResponse, OAuth2Client, RefreshOptions} from './oauth2client';

export interface ImpersonatedOptions extends RefreshOptions {
  /**
   * Client used to perform exchange for impersonated client.
   */
  sourceClient?: OAuth2Client;
  /**
   * The service account to impersonate.
   */
  targetPrincipal?: string;
  /**
   * Scopes to request during the authorization grant.
   */
  targetScopes?: string[];
  /**
   * The chained list of delegates required to grant the final access_token.
   */
  delegates?: string[];
  /**
   * Number of seconds the delegated credential should be valid.
   */
  lifetime?: number | 3600;
  /**
   * API endpoint to fetch token from.
   */
  endpoint?: string;
}

export interface TokenResponse {
  accessToken: string;
  expireTime: string;
}

export class Impersonated extends OAuth2Client {
  private sourceClient: OAuth2Client;
  private targetPrincipal: string;
  private targetScopes: string[];
  private delegates: string[];
  private lifetime: number;
  private endpoint: string;

  /**
   * Impersonated service account credentials.
   *
   * Create a new access token by impersonating another service account.
   *
   * Impersonated Credentials allowing credentials issued to a user or
   * service account to impersonate another. The source project using
   * Impersonated Credentials must enable the "IAMCredentials" API.
   * Also, the target service account must grant the orginating principal
   * the "Service Account Token Creator" IAM role.
   *
   * @param credentials the service account email address.
   * @param sourceClient the source credential used as to acquire the
   * impersonated credentials
   * @param targetPrincipal the service account to impersonate.
   * @param delegates the chained list of delegates required to grant the
   *  final access_token. If set, the sequence of identities must have
   * "Service Account Token Creator" capability granted to the preceding
   * identity. For example, if set to [serviceAccountB, serviceAccountC],
   * the sourceCredential must have the Token Creator role on serviceAccountB.
   * serviceAccountB must have the Token Creator on serviceAccountC.
   * Finally, C must have Token Creator on target_principal.
   * If left unset, sourceCredential must have that role on targetPrincipal.
   * @param targetScopes scopes to request during the authorization grant.
   * @param lifetime number of seconds the delegated credential should be
   * valid for up to 3600 seconds by default, or 43,200 seconds by
   * extending the token's lifetime, see:
   * https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials#sa-credentials-oauth
   * @param endpoint api endpoint override.
   */
  constructor(options: ImpersonatedOptions = {}) {
    super(options);
    this.credentials = {
      expiry_date: 1,
      refresh_token: 'impersonated-placeholder',
    };
    this.sourceClient = options.sourceClient ?? new OAuth2Client();
    this.targetPrincipal = options.targetPrincipal ?? '';
    this.delegates = options.delegates ?? [];
    this.targetScopes = options.targetScopes ?? [];
    this.lifetime = options.lifetime ?? 3600;
    this.endpoint = options.endpoint ?? 'https://iamcredentials.googleapis.com';
  }

  /**
   * Refreshes the access token.
   * @param refreshToken Unused parameter
   */
  protected async refreshToken(
    refreshToken?: string | null
  ): Promise<GetTokenResponse> {
    try {
      await this.sourceClient.getAccessToken();
      const name = 'projects/-/serviceAccounts/' + this.targetPrincipal;
      const u = `${this.endpoint}/v1/${name}:generateAccessToken`;
      const body = {
        delegates: this.delegates,
        scope: this.targetScopes,
        lifetime: this.lifetime + 's',
      };
      const res = await this.sourceClient.request<TokenResponse>({
        url: u,
        data: body,
        method: 'POST',
      });
      const tokenResponse = res.data;
      this.credentials.access_token = tokenResponse.accessToken;
      this.credentials.expiry_date =
        Date.parse(tokenResponse.expireTime) / 1000;
      return {
        tokens: this.credentials,
        res,
      };
    } catch (error) {
      const status = error?.response?.data?.error?.status;
      const message = error?.response?.data?.error?.message;
      if (status && message) {
        error.message = `${status}: unable to impersonate: ${message}`;
        throw error;
      } else {
        error.message = `unable to impersonate: ${error}`;
        throw error;
      }
    }
  }
}
