// Copyright 2020 Google LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// sample-metadata:
//   title: ID Tokens for Serverless
//   description: Requests a Cloud Run or Cloud Functions URL with an ID Token.
//   usage: node idtokens-serverless.js <url> [<target-audience>]

'use strict';

function main(
  url = 'https://service-1234-uc.a.run.app',
  targetAudience = null
) {
   if (!targetAudience) {
    // Use the target service's hostname as the target audience for requests.
    // (For example: https://my-cloud-run-service.run.app)
    const {URL} = require('url');
    targetAudience = new URL(url).origin;
  }
  
  // [START google_auth_idtoken_serverless]
  // [START run_service_to_service_auth]
  // [START functions_bearer_token]
  /**
   * TODO(developer): Uncomment these variables before running the sample.
   */
    
  // Example: https://my-cloud-run-service.run.app/books/delete/12345
  // const url = 'https://TARGET_HOSTNAME/TARGET_URL';
    
  // Example: https://my-cloud-run-service.run.app/
  // const targetAudience = 'https://TARGET_HOSTNAME/';
  
  const {GoogleAuth} = require('google-auth-library');
  const auth = new GoogleAuth();

  async function request() {
    console.info(`request ${url} with target audience ${targetAudience}`);
    const client = await auth.getIdTokenClient(targetAudience);
    const res = await client.request({url});
    console.info(res.data);
  }

  request().catch(err => {
    console.error(err.message);
    process.exitCode = 1;
  });
  // [END functions_bearer_token]
  // [END run_service_to_service_auth]
  // [END google_auth_idtoken_serverless]
}

const args = process.argv.slice(2);
main(...args);
