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

import {GoogleToken} from 'gtoken';
import * as stream from 'stream';

import {CredentialBody, Credentials, JWTInput} from './credentials';
import {IdTokenProvider} from './idtokenclient';
import {JWTAccess} from './jwtaccess';
import {
  GetTokenResponse,
  OAuth2Client,
  RefreshOptions,
  RequestMetadataResponse,
} from './oauth2client';

export interface JWTOptions extends RefreshOptions {
  email?: string;
  keyFile?: string;
  key?: string;
  keyId?: string;
  scopes?: string | string[];
  subject?: string;
  additionalClaims?: {};
}

export class JWT extends OAuth2Client implements IdTokenProvider {
  email?: string;
  keyFile?: string;
  key?: string;
  keyId?: string;
  defaultScopes?: string | string[];
  scopes?: string | string[];
  scope?: string;
  subject?: string;
  gtoken?: GoogleToken;
  additionalClaims?: {};
  useJWTAccessAlways?: boolean;
  defaultServicePath?: string;
  private access?: JWTAccess;

  /**
   * JWT service account credentials.
   *
   * Retrieve access token using gtoken.
   *
   * @param email service account email address.
   * @param keyFile path to private key file.
   * @param key value of key
   * @param scopes list of requested scopes or a single scope.
   * @param subject impersonated account's email address.
   * @param key_id the ID of the key
   */
  constructor(options: JWTOptions);
  constructor(
    email?: string,
    keyFile?: string,
    key?: string,
    scopes?: string | string[],
    subject?: string,
    keyId?: string
  );
  constructor(
    optionsOrEmail?: string | JWTOptions,
    keyFile?: string,
    key?: string,
    scopes?: string | string[],
    subject?: string,
    keyId?: string
  ) {
    const opts =
      optionsOrEmail && typeof optionsOrEmail === 'object'
        ? optionsOrEmail
        : {email: optionsOrEmail, keyFile, key, keyId, scopes, subject};
    super({
      eagerRefreshThresholdMillis: opts.eagerRefreshThresholdMillis,
      forceRefreshOnFailure: opts.forceRefreshOnFailure,
    });
    this.email = opts.email;
    this.keyFile = opts.keyFile;
    this.key = opts.key;
    this.keyId = opts.keyId;
    this.scopes = opts.scopes;
    this.subject = opts.subject;
    this.additionalClaims = opts.additionalClaims;
    this.credentials = {refresh_token: 'jwt-placeholder', expiry_date: 1};
  }

  /**
   * Creates a copy of the credential with the specified scopes.
   * @param scopes List of requested scopes or a single scope.
   * @return The cloned instance.
   */
  createScoped(scopes?: string | string[]) {
    return new JWT({
      email: this.email,
      keyFile: this.keyFile,
      key: this.key,
      keyId: this.keyId,
      scopes,
      subject: this.subject,
      additionalClaims: this.additionalClaims,
    });
  }

  /**
   * Obtains the metadata to be sent with the request.
   *
   * @param url the URI being authorized.
   */
  protected async getRequestMetadataAsync(
    url?: string | null
  ): Promise<RequestMetadataResponse> {
    if (!this.apiKey && !this.hasUserScopes() && url) {
      if (
        this.additionalClaims &&
        (
          this.additionalClaims as {
            target_audience: string;
          }
        ).target_audience
      ) {
        const {tokens} = await this.refreshToken();
        return {
          headers: this.addSharedMetadataHeaders({
            Authorization: `Bearer ${tokens.id_token}`,
          }),
        };
      } else {
        // no scopes have been set, but a uri has been provided. Use JWTAccess
        // credentials.
        if (!this.access) {
          this.access = new JWTAccess(
            this.email,
            this.key,
            this.keyId,
            this.eagerRefreshThresholdMillis
          );
        }
        const headers = await this.access.getRequestHeaders(
          url,
          this.additionalClaims
        );
        return {headers: this.addSharedMetadataHeaders(headers)};
      }
    } else if (this.hasAnyScopes() || this.apiKey) {
      return super.getRequestMetadataAsync(url);
    } else {
      // If no audience, apiKey, or scopes are provided, we should not attempt
      // to populate any headers:
      return {headers: {}};
    }
  }

  /**
   * Fetches an ID token.
   * @param targetAudience the audience for the fetched ID token.
   */
  async fetchIdToken(targetAudience: string): Promise<string> {
    // Create a new gToken for fetching an ID token
    const gtoken = new GoogleToken({
      iss: this.email,
      sub: this.subject,
      scope: this.scopes || this.defaultScopes,
      keyFile: this.keyFile,
      key: this.key,
      additionalClaims: {target_audience: targetAudience},
    });
    await gtoken.getToken({
      forceRefresh: true,
    });
    if (!gtoken.idToken) {
      throw new Error('Unknown error: Failed to fetch ID token');
    }
    return gtoken.idToken;
  }

  /**
   * Determine if there are currently scopes available.
   */
  private hasUserScopes() {
    if (!this.scopes) {
      return false;
    }
    return this.scopes.length > 0;
  }

  /**
   * Are there any default or user scopes defined.
   */
  private hasAnyScopes() {
    if (this.scopes && this.scopes.length > 0) return true;
    if (this.defaultScopes && this.defaultScopes.length > 0) return true;
    return false;
  }

  /**
   * Get the initial access token using gToken.
   * @param callback Optional callback.
   * @returns Promise that resolves with credentials
   */
  authorize(): Promise<Credentials>;
  authorize(callback: (err: Error | null, result?: Credentials) => void): void;
  authorize(
    callback?: (err: Error | null, result?: Credentials) => void
  ): Promise<Credentials> | void {
    if (callback) {
      this.authorizeAsync().then(r => callback(null, r), callback);
    } else {
      return this.authorizeAsync();
    }
  }

  private async authorizeAsync(): Promise<Credentials> {
    const result = await this.refreshToken();
    if (!result) {
      throw new Error('No result returned');
    }
    this.credentials = result.tokens;
    this.credentials.refresh_token = 'jwt-placeholder';
    this.key = this.gtoken!.key;
    this.email = this.gtoken!.iss;
    return result.tokens;
  }

  /**
   * Refreshes the access token.
   * @param refreshToken ignored
   * @private
   */
  protected async refreshTokenNoCache(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    refreshToken?: string | null
  ): Promise<GetTokenResponse> {
    const gtoken = this.createGToken();
    const token = await gtoken.getToken({
      forceRefresh: this.isTokenExpiring(),
    });
    const tokens = {
      access_token: token.access_token,
      token_type: 'Bearer',
      expiry_date: gtoken.expiresAt,
      id_token: gtoken.idToken,
    };
    this.emit('tokens', tokens);
    return {res: null, tokens};
  }

  /**
   * Create a gToken if it doesn't already exist.
   */
  private createGToken(): GoogleToken {
    if (!this.gtoken) {
      this.gtoken = new GoogleToken({
        iss: this.email,
        sub: this.subject,
        scope: this.scopes || this.defaultScopes,
        keyFile: this.keyFile,
        key: this.key,
        additionalClaims: this.additionalClaims,
      });
    }
    return this.gtoken;
  }

  /**
   * Create a JWT credentials instance using the given input options.
   * @param json The input object.
   */
  fromJSON(json: JWTInput): void {
    if (!json) {
      throw new Error(
        'Must pass in a JSON object containing the service account auth settings.'
      );
    }
    if (!json.client_email) {
      throw new Error(
        'The incoming JSON object does not contain a client_email field'
      );
    }
    if (!json.private_key) {
      throw new Error(
        'The incoming JSON object does not contain a private_key field'
      );
    }
    // Extract the relevant information from the json key file.
    this.email = json.client_email;
    this.key = json.private_key;
    this.keyId = json.private_key_id;
    this.projectId = json.project_id;
    this.quotaProjectId = json.quota_project_id;
  }

  /**
   * Create a JWT credentials instance using the given input stream.
   * @param inputStream The input stream.
   * @param callback Optional callback.
   */
  fromStream(inputStream: stream.Readable): Promise<void>;
  fromStream(
    inputStream: stream.Readable,
    callback: (err?: Error | null) => void
  ): void;
  fromStream(
    inputStream: stream.Readable,
    callback?: (err?: Error | null) => void
  ): void | Promise<void> {
    if (callback) {
      this.fromStreamAsync(inputStream).then(() => callback(), callback);
    } else {
      return this.fromStreamAsync(inputStream);
    }
  }

  private fromStreamAsync(inputStream: stream.Readable) {
    return new Promise<void>((resolve, reject) => {
      if (!inputStream) {
        throw new Error(
          'Must pass in a stream containing the service account auth settings.'
        );
      }
      let s = '';
      inputStream
        .setEncoding('utf8')
        .on('error', reject)
        .on('data', chunk => (s += chunk))
        .on('end', () => {
          try {
            const data = JSON.parse(s);
            this.fromJSON(data);
            resolve();
          } catch (e) {
            reject(e);
          }
        });
    });
  }

  /**
   * Creates a JWT credentials instance using an API Key for authentication.
   * @param apiKey The API Key in string form.
   */
  fromAPIKey(apiKey: string): void {
    if (typeof apiKey !== 'string') {
      throw new Error('Must provide an API Key string.');
    }
    this.apiKey = apiKey;
  }

  /**
   * Using the key or keyFile on the JWT client, obtain an object that contains
   * the key and the client email.
   */
  async getCredentials(): Promise<CredentialBody> {
    if (this.key) {
      return {private_key: this.key, client_email: this.email};
    } else if (this.keyFile) {
      const gtoken = this.createGToken();
      const creds = await gtoken.getCredentials(this.keyFile);
      return {private_key: creds.privateKey, client_email: creds.clientEmail};
    }
    throw new Error('A key or a keyFile must be provided to getCredentials.');
  }
}
