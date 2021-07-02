// Copyright 2015 Google LLC
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

import * as stream from 'stream';
import {JWTInput} from './credentials';
import {GetTokenResponse, OAuth2Client, RefreshOptions} from './oauth2client';

export interface UserRefreshClientOptions extends RefreshOptions {
  clientId?: string;
  clientSecret?: string;
  refreshToken?: string;
}

export class UserRefreshClient extends OAuth2Client {
  // TODO: refactor tests to make this private
  // In a future gts release, the _propertyName rule will be lifted.
  // This is also a hard one because `this.refreshToken` is a function.
  _refreshToken?: string | null;
  public useJWTAccessAlways?: boolean;
  public defaultServicePath?: string;

  /**
   * User Refresh Token credentials.
   *
   * @param clientId The authentication client ID.
   * @param clientSecret The authentication client secret.
   * @param refreshToken The authentication refresh token.
   */
  constructor(clientId?: string, clientSecret?: string, refreshToken?: string);
  constructor(options: UserRefreshClientOptions);
  constructor(clientId?: string, clientSecret?: string, refreshToken?: string);
  constructor(
    optionsOrClientId?: string | UserRefreshClientOptions,
    clientSecret?: string,
    refreshToken?: string,
    eagerRefreshThresholdMillis?: number,
    forceRefreshOnFailure?: boolean
  ) {
    const opts =
      optionsOrClientId && typeof optionsOrClientId === 'object'
        ? optionsOrClientId
        : {
            clientId: optionsOrClientId,
            clientSecret,
            refreshToken,
            eagerRefreshThresholdMillis,
            forceRefreshOnFailure,
          };
    super({
      clientId: opts.clientId,
      clientSecret: opts.clientSecret,
      eagerRefreshThresholdMillis: opts.eagerRefreshThresholdMillis,
      forceRefreshOnFailure: opts.forceRefreshOnFailure,
    });
    this._refreshToken = opts.refreshToken;
    this.credentials.refresh_token = opts.refreshToken;
  }

  /**
   * Refreshes the access token.
   * @param refreshToken An ignored refreshToken..
   * @param callback Optional callback.
   */
  protected async refreshTokenNoCache(
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    refreshToken?: string | null
  ): Promise<GetTokenResponse> {
    return super.refreshTokenNoCache(this._refreshToken);
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * options.
   * @param json The input object.
   */
  fromJSON(json: JWTInput): void {
    if (!json) {
      throw new Error(
        'Must pass in a JSON object containing the user refresh token'
      );
    }
    if (json.type !== 'authorized_user') {
      throw new Error(
        'The incoming JSON object does not have the "authorized_user" type'
      );
    }
    if (!json.client_id) {
      throw new Error(
        'The incoming JSON object does not contain a client_id field'
      );
    }
    if (!json.client_secret) {
      throw new Error(
        'The incoming JSON object does not contain a client_secret field'
      );
    }
    if (!json.refresh_token) {
      throw new Error(
        'The incoming JSON object does not contain a refresh_token field'
      );
    }
    this._clientId = json.client_id;
    this._clientSecret = json.client_secret;
    this._refreshToken = json.refresh_token;
    this.credentials.refresh_token = json.refresh_token;
    this.quotaProjectId = json.quota_project_id;
  }

  /**
   * Create a UserRefreshClient credentials instance using the given input
   * stream.
   * @param inputStream The input stream.
   * @param callback Optional callback.
   */
  fromStream(inputStream: stream.Readable): Promise<void>;
  fromStream(
    inputStream: stream.Readable,
    callback: (err?: Error) => void
  ): void;
  fromStream(
    inputStream: stream.Readable,
    callback?: (err?: Error) => void
  ): void | Promise<void> {
    if (callback) {
      this.fromStreamAsync(inputStream).then(() => callback(), callback);
    } else {
      return this.fromStreamAsync(inputStream);
    }
  }

  private async fromStreamAsync(inputStream: stream.Readable): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      if (!inputStream) {
        return reject(
          new Error('Must pass in a stream containing the user refresh token.')
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
            return resolve();
          } catch (err) {
            return reject(err);
          }
        });
    });
  }
}
