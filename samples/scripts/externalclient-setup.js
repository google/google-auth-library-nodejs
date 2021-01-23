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

// This script is used to generate the project configurations needed to
// end-to-end test workload identity pools in the Auth library, specifically
// file-sourced, URL-sourced OIDC-based credentials and AWS credentials.
// This is done via the sample test: samples/test/externalclient.test.js.
//
// In order to run this script, the GOOGLE_APPLICATION_CREDENTIALS environment
// variable needs to be set to point to a service account key file.
// Additional AWS related information (AWS account ID and AWS role name) also
// need to be provided in this file. Detailed instructions are documented below.
//
// GCP project changes:
// --------------------
// The following IAM roles need to be set on the service account:
// 1. IAM Workload Identity Pool Admin (needed to create resources for workload
//    identity pools).
// 2. Security Admin (needed to get and set IAM policies).
// 3. Service Account Token Creator (needed to generate Google ID tokens and
//    access tokens).
//
// The following APIs need to be enabled on the project:
// 1. Identity and Access Management (IAM) API.
// 2. IAM Service Account Credentials API.
// 3. Cloud Resource Manager API.
// 4. The API being accessed in the test, eg. DNS.
//
// AWS developer account changes:
// ------------------------------
// For testing AWS credentials, the following are needed:
// 1. An AWS developer account is needed. The account ID will need to
//    be provided in the configuration object below.
// 2. A role for web identity federation. This will also need to be provided
//    in the configuration object below.
//    - An OIDC Google identity provider needs to be created with the following:
//      issuer: accounts.google.com
//      audience: Use the client_id of the service account.
//    - A role for OIDC web identity federation is needed with the created
//      Google provider as a trusted entity:
//      "accounts.google.com:aud": "$CLIENT_ID"
//    The role creation steps are documented at:
//    https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
//
// This script needs to be run once. It will do the following:
// 1. Create a random workload identity pool.
// 2. Create a random OIDC provider in that pool which uses the
//    accounts.google.com as the issuer and the default STS audience as the
//    allowed audience. This audience will be validated on STS token exchange.
// 3. Enable OIDC tokens generated by the current service account to impersonate
//    the service account. (Identified by the OIDC token sub field which is the
//    service account client ID).
// 4. Create a random AWS provider in that pool which uses the provided AWS
//    account ID.
// 5. Enable AWS provider to impersonate the service account. (Principal is
//    identified by the AWS role name).
// 6. Print out the STS audience fields associated with the created providers
//    after the setup completes successfully so that they can be used in the
//    tests. These will be copied and used as the global AUDIENCE_OIDC and
//    AUDIENCE_AWS constants in samples/test/externalclient.test.js.
//    An additional AWS_ROLE_ARN field will be printed out and also needs
//    to be copied to the test file. This will be used as the AWS role for
//    AssumeRoleWithWebIdentity when federating from GCP to AWS.
// The same service account used for this setup script should be used for
// the test script.
//
// It is safe to run the setup script again. A new pool is created and new
// audiences are printed. If run multiple times, it is advisable to delete
// unused pools. Note that deleted pools are soft deleted and may remain for
// a while before they are completely deleted. The old pool ID cannot be used
// in the meantime.

const fs = require('fs');
const {promisify} = require('util');
const {GoogleAuth} = require('google-auth-library');

const readFile = promisify(fs.readFile);

/**
 * Generates a random string of the specified length, optionally using the
 * specified alphabet.
 *
 * @param {number} length The length of the string to generate.
 * @return {string} A random string of the provided length.
 */
const generateRandomString = length => {
  const chars = [];
  const allowedChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  while (length > 0) {
    chars.push(
      allowedChars.charAt(Math.floor(Math.random() * allowedChars.length))
    );
    length--;
  }
  return chars.join('');
};

/**
 * Creates a workload identity pool with an OIDC provider which will accept
 * Google OIDC tokens generated from the current service account where the token
 * will have sub as the service account client ID and the audience as the
 * created identity pool STS audience.
 * The steps followed here mirror the instructions for configuring federation
 * with an OIDC provider illustrated at:
 * https://cloud.google.com/iam/docs/access-resources-oidc
 * This will also create an AWS provider in the same workload identity pool
 * using the AWS account ID and AWS ARN role name provided.
 * The steps followed here mirror the instructions for configuring federation
 * with an AWS provider illustrated at:
 * https://cloud.google.com/iam/docs/access-resources-aws
 * @param {Object} config An object containing additional data needed to
 *   configure the external account client setup.
 * @return {Promise<Object>} A promise that resolves with an object containing
 *   the STS audience corresponding with the generated workload identity pool
 *   OIDC provider and AWS provider.
 */
async function main(config) {
  let response;
  const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    throw new Error('No GOOGLE_APPLICATION_CREDENTIALS env var is available');
  }
  const keys = JSON.parse(await readFile(keyFile, 'utf8'));
  const suffix = generateRandomString(10);
  const poolId = `pool-${suffix}`;
  const oidcProviderId = `oidc-${suffix}`;
  const awsProviderId = `aws-${suffix}`;
  const projectId = keys.project_id;
  const clientEmail = keys.client_email;
  const sub = keys.client_id;
  const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform',
  });

  // TODO: switch to using IAM client SDK once v1 API has all the v1beta
  // changes.
  // https://cloud.google.com/iam/docs/reference/rest/v1beta/projects.locations.workloadIdentityPools
  // https://github.com/googleapis/google-api-nodejs-client/tree/master/src/apis/iam

  // Create the workload identity pool.
  response = await auth.request({
    url:
      `https://iam.googleapis.com/v1beta/projects/${projectId}/` +
      `locations/global/workloadIdentityPools?workloadIdentityPoolId=${poolId}`,
    method: 'POST',
    data: {
      displayName: 'Test workload identity pool',
      description: 'Test workload identity pool for Node.js',
    },
  });
  // Populate the audience field. This will be used by the tests, specifically
  // the credential configuration file.
  const poolResourcePath = response.data.name.split('/operations')[0];
  const oidcAudience = `//iam.googleapis.com/${poolResourcePath}/providers/${oidcProviderId}`;
  const awsAudience = `//iam.googleapis.com/${poolResourcePath}/providers/${awsProviderId}`;

  // Allow service account impersonation.
  // Get the existing IAM policity bindings on the current service account.
  response = await auth.request({
    url:
      `https://iam.googleapis.com/v1/projects/${projectId}/` +
      `serviceAccounts/${clientEmail}:getIamPolicy`,
    method: 'POST',
  });
  const bindings = response.data.bindings || [];
  // If not found, add roles/iam.workloadIdentityUser role binding to the
  // workload identity pool member.
  // For OIDC providers, we will use the value mapped to google.subject.
  // This is the sub field of the OIDC token which is the service account
  // client_id.
  // For AWS providers, we will use the AWS role attribute. This will be the
  // assumed role by AssumeRoleWithWebIdentity.
  let found = false;
  bindings.forEach(binding => {
    if (binding.role === 'roles/iam.workloadIdentityUser') {
      found = true;
      binding.members = [
        `principal://iam.googleapis.com/${poolResourcePath}/subject/${sub}`,
        `principalSet://iam.googleapis.com/${poolResourcePath}/` +
          `attribute.aws_role/arn:aws:sts::${config.awsAccountId}:assumed-role/` +
          `${config.awsRoleName}`,
      ];
    }
  });
  if (!found) {
    bindings.push({
      role: 'roles/iam.workloadIdentityUser',
      members: [
        `principal://iam.googleapis.com/${poolResourcePath}/subject/${sub}`,
        `principalSet://iam.googleapis.com/${poolResourcePath}/` +
          `attribute.aws_role/arn:aws:sts::${config.awsAccountId}:assumed-role/` +
          `${config.awsRoleName}`,
      ],
    });
  }
  await auth.request({
    url:
      `https://iam.googleapis.com/v1/projects/${projectId}/` +
      `serviceAccounts/${clientEmail}:setIamPolicy`,
    method: 'POST',
    data: {
      policy: {
        bindings,
      },
    },
  });

  // Create an OIDC provider. This will use the accounts.google.com issuer URL.
  // This will use the STS audience as the OIDC token audience.
  await auth.request({
    url:
      `https://iam.googleapis.com/v1beta/projects/${projectId}/` +
      `locations/global/workloadIdentityPools/${poolId}/providers?` +
      `workloadIdentityPoolProviderId=${oidcProviderId}`,
    method: 'POST',
    data: {
      displayName: 'Test OIDC provider',
      description: 'Test OIDC provider for Node.js',
      attributeMapping: {
        'google.subject': 'assertion.sub',
      },
      oidc: {
        issuerUri: 'https://accounts.google.com',
        allowedAudiences: [oidcAudience],
      },
    },
  });

  // Create an AWS provider.
  await auth.request({
    url:
      `https://iam.googleapis.com/v1beta/projects/${projectId}/` +
      `locations/global/workloadIdentityPools/${poolId}/providers?` +
      `workloadIdentityPoolProviderId=${awsProviderId}`,
    method: 'POST',
    data: {
      displayName: 'Test AWS provider',
      description: 'Test AWS provider for Node.js',
      aws: {
        accountId: config.awsAccountId,
      },
    },
  });

  return {
    oidcAudience,
    awsAudience,
  };
}

// Additional configuration input needed to configure the workload
// identity pool. For AWS tests, an AWS developer account is needed.
// The following AWS prerequisite setup is needed.
// 1. An OIDC Google identity provider needs to be created with the following:
//    issuer: accounts.google.com
//    audience: Use the client_id of the service account.
// 2. A role for OIDC web identity federation is needed with the created Google
//    provider as a trusted entity:
//    "accounts.google.com:aud": "$CLIENT_ID"
// The steps are documented at:
// https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html
const config = {
  // The role name for web identity federation.
  awsRoleName: 'ci-nodejs-test',
  // The AWS account ID.
  awsAccountId: '077071391996',
};

// On execution, the following will be printed to the screen:
// AUDIENCE_OIDC: generated OIDC provider audience.
// AUDIENCE_AWS: generated AWS provider audience.
// AWS_ROLE_ARN: This is the AWS role for AssumeRoleWithWebIdentity.
// This should be updated in test/externalclient.test.js.
// Some delay is needed before running the tests in test/externalclient.test.js
// to ensure IAM policies propagate before running sample tests.
// Normally 1-2 minutes should suffice.
main(config)
  .then(audiences => {
    console.log(
      'The following constants need to be set in test/externalclient.test.js'
    );
    console.log(`AUDIENCE_OIDC='${audiences.oidcAudience}'`);
    console.log(`AUDIENCE_AWS='${audiences.awsAudience}'`);
    console.log(
      `AWS_ROLE_ARN='arn:aws::iam::${config.awsAccountId}:role/${config.awsRoleName}'`
    );
  })
  .catch(console.error);
