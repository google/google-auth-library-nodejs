[//]: # "This README.md file is auto-generated, all changes to this file will be lost."
[//]: # "To regenerate it, use `python -m synthtool`."
<img src="https://avatars2.githubusercontent.com/u/2810941?v=3&s=96" alt="Google Cloud Platform logo" title="Google Cloud Platform" align="right" height="96" width="96"/>

# [Google Auth Library: Node.js Client](https://github.com/googleapis/google-auth-library-nodejs)

[![release level](https://img.shields.io/badge/release%20level-general%20availability%20%28GA%29-brightgreen.svg?style=flat)](https://cloud.google.com/terms/launch-stages)
[![npm version](https://img.shields.io/npm/v/google-auth-library.svg)](https://www.npmjs.org/package/google-auth-library)
[![codecov](https://img.shields.io/codecov/c/github/googleapis/google-auth-library-nodejs/master.svg?style=flat)](https://codecov.io/gh/googleapis/google-auth-library-nodejs)




This is Google's officially supported [node.js](http://nodejs.org/) client library for using OAuth 2.0 authorization and authentication with Google APIs.


A comprehensive list of changes in each version may be found in
[the CHANGELOG](https://github.com/googleapis/google-auth-library-nodejs/blob/master/CHANGELOG.md).

* [Google Auth Library Node.js Client API Reference][client-docs]
* [Google Auth Library Documentation][product-docs]
* [github.com/googleapis/google-auth-library-nodejs](https://github.com/googleapis/google-auth-library-nodejs)

Read more about the client libraries for Cloud APIs, including the older
Google APIs Client Libraries, in [Client Libraries Explained][explained].

[explained]: https://cloud.google.com/apis/docs/client-libraries-explained

**Table of contents:**


* [Quickstart](#quickstart)

  * [Installing the client library](#installing-the-client-library)

* [Samples](#samples)
* [Versioning](#versioning)
* [Contributing](#contributing)
* [License](#license)

## Quickstart

### Installing the client library

```bash
npm install google-auth-library
```

## Ways to authenticate
This library provides a variety of ways to authenticate to your Google services.
- [Application Default Credentials](#choosing-the-correct-credential-type-automatically) - Use Application Default Credentials when you use a single identity for all users in your application. Especially useful for applications running on Google Cloud. Application Default Credentials also support workload identity federation to access Google Cloud resources from non-Google Cloud platforms.
- [OAuth 2](#oauth2) - Use OAuth2 when you need to perform actions on behalf of the end user.
- [JSON Web Tokens](#json-web-tokens) - Use JWT when you are using a single identity for all users. Especially useful for server->server or server->API communication.
- [Google Compute](#compute) - Directly use a service account on Google Cloud Platform. Useful for server->server or server->API communication.
- [Workload Identity Federation](#workload-identity-federation) - Use workload identity federation to access Google Cloud resources from Amazon Web Services (AWS), Microsoft Azure or any identity provider that supports OpenID Connect (OIDC).
- [Impersonated Credentials Client](#impersonated-credentials-client) - access protected resources on behalf of another service account.

## Application Default Credentials
This library provides an implementation of [Application Default Credentials](https://cloud.google.com/docs/authentication/getting-started)for Node.js. The [Application Default Credentials](https://cloud.google.com/docs/authentication/getting-started) provide a simple way to get authorization credentials for use in calling Google APIs.

They are best suited for cases when the call needs to have the same identity and authorization level for the application independent of the user. This is the recommended approach to authorize calls to Cloud APIs, particularly when you're building an application that uses Google Cloud Platform.

Application Default Credentials also support workload identity federation to access Google Cloud resources from non-Google Cloud platforms including Amazon Web Services (AWS), Microsoft Azure or any identity provider that supports OpenID Connect (OIDC). Workload identity federation is recommended for non-Google Cloud environments as it avoids the need to download, manage and store service account private keys locally, see: [Workload Identity Federation](#workload-identity-federation).

#### Download your Service Account Credentials JSON file

To use Application Default Credentials, You first need to download a set of JSON credentials for your project. Go to **APIs & Auth** > **Credentials** in the [Google Developers Console](https://console.cloud.google.com/) and select **Service account** from the **Add credentials** dropdown.

> This file is your *only copy* of these credentials. It should never be
> committed with your source code, and should be stored securely.

Once downloaded, store the path to this file in the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.

#### Enable the API you want to use

Before making your API call, you must be sure the API you're calling has been enabled. Go to **APIs & Auth** > **APIs** in the [Google Developers Console](https://console.cloud.google.com/) and enable the APIs you'd like to call. For the example below, you must enable the `DNS API`.


#### Choosing the correct credential type automatically

Rather than manually creating an OAuth2 client, JWT client, or Compute client, the auth library can create the correct credential type for you, depending upon the environment your code is running under.

For example, a JWT auth client will be created when your code is running on your local developer machine, and a Compute client will be created when the same code is running on Google Cloud Platform. If you need a specific set of scopes, you can pass those in the form of a string or an array to the `GoogleAuth` constructor.

The code below shows how to retrieve a default credential type, depending upon the runtime environment.

```js
const {GoogleAuth} = require('google-auth-library');

/**
* Instead of specifying the type of client you'd like to use (JWT, OAuth2, etc)
* this library will automatically choose the right client based on the environment.
*/
async function main() {
  const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform'
  });
  const client = await auth.getClient();
  const projectId = await auth.getProjectId();
  const url = `https://dns.googleapis.com/dns/v1/projects/${projectId}`;
  const res = await client.request({ url });
  console.log(res.data);
}

main().catch(console.error);
```

## OAuth2

This library comes with an [OAuth2](https://developers.google.com/identity/protocols/OAuth2) client that allows you to retrieve an access token and refreshes the token and retry the request seamlessly if you also provide an `expiry_date` and the token is expired. The basics of Google's OAuth2 implementation is explained on [Google Authorization and Authentication documentation](https://developers.google.com/accounts/docs/OAuth2Login).

In the following examples, you may need a `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URL`. You can find these pieces of information by going to the [Developer Console](https://console.cloud.google.com/), clicking your project > APIs & auth > credentials.

For more information about OAuth2 and how it works, [see here](https://developers.google.com/identity/protocols/OAuth2).

#### A complete OAuth2 example

Let's take a look at a complete example.

``` js
const {OAuth2Client} = require('google-auth-library');
const http = require('http');
const url = require('url');
const open = require('open');
const destroyer = require('server-destroy');

// Download your OAuth2 configuration from the Google
const keys = require('./oauth2.keys.json');

/**
* Start by acquiring a pre-authenticated oAuth2 client.
*/
async function main() {
  const oAuth2Client = await getAuthenticatedClient();
  // Make a simple request to the People API using our pre-authenticated client. The `request()` method
  // takes an GaxiosOptions object.  Visit https://github.com/JustinBeckwith/gaxios.
  const url = 'https://people.googleapis.com/v1/people/me?personFields=names';
  const res = await oAuth2Client.request({url});
  console.log(res.data);

  // After acquiring an access_token, you may want to check on the audience, expiration,
  // or original scopes requested.  You can do that with the `getTokenInfo` method.
  const tokenInfo = await oAuth2Client.getTokenInfo(
    oAuth2Client.credentials.access_token
  );
  console.log(tokenInfo);
}

/**
* Create a new OAuth2Client, and go through the OAuth2 content
* workflow.  Return the full client to the callback.
*/
function getAuthenticatedClient() {
  return new Promise((resolve, reject) => {
    // create an oAuth client to authorize the API call.  Secrets are kept in a `keys.json` file,
    // which should be downloaded from the Google Developers Console.
    const oAuth2Client = new OAuth2Client(
      keys.web.client_id,
      keys.web.client_secret,
      keys.web.redirect_uris[0]
    );

    // Generate the url that will be used for the consent dialog.
    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: 'https://www.googleapis.com/auth/userinfo.profile',
    });

    // Open an http server to accept the oauth callback. In this simple example, the
    // only request to our webserver is to /oauth2callback?code=<code>
    const server = http
      .createServer(async (req, res) => {
        try {
          if (req.url.indexOf('/oauth2callback') > -1) {
            // acquire the code from the querystring, and close the web server.
            const qs = new url.URL(req.url, 'http://localhost:3000')
              .searchParams;
            const code = qs.get('code');
            console.log(`Code is ${code}`);
            res.end('Authentication successful! Please return to the console.');
            server.destroy();

            // Now that we have the code, use that to acquire tokens.
            const r = await oAuth2Client.getToken(code);
            // Make sure to set the credentials on the OAuth2 client.
            oAuth2Client.setCredentials(r.tokens);
            console.info('Tokens acquired.');
            resolve(oAuth2Client);
          }
        } catch (e) {
          reject(e);
        }
      })
      .listen(3000, () => {
        // open the browser to the authorize url to start the workflow
        open(authorizeUrl, {wait: false}).then(cp => cp.unref());
      });
    destroyer(server);
  });
}

main().catch(console.error);
```

#### Handling token events

This library will automatically obtain an `access_token`, and automatically refresh the `access_token` if a `refresh_token` is present.  The `refresh_token` is only returned on the [first authorization](https://github.com/googleapis/google-api-nodejs-client/issues/750#issuecomment-304521450), so if you want to make sure you store it safely. An easy way to make sure you always store the most recent tokens is to use the `tokens` event:

```js
const client = await auth.getClient();

client.on('tokens', (tokens) => {
  if (tokens.refresh_token) {
    // store the refresh_token in my database!
    console.log(tokens.refresh_token);
  }
  console.log(tokens.access_token);
});

const url = `https://dns.googleapis.com/dns/v1/projects/${projectId}`;
const res = await client.request({ url });
// The `tokens` event would now be raised if this was the first request
```

#### Retrieve access token
With the code returned, you can ask for an access token as shown below:

``` js
const tokens = await oauth2Client.getToken(code);
// Now tokens contains an access_token and an optional refresh_token. Save them.
oauth2Client.setCredentials(tokens);
```

#### Obtaining a new Refresh Token
If you need to obtain a new `refresh_token`, ensure the call to `generateAuthUrl` sets the `access_type` to `offline`.  The refresh token will only be returned for the first authorization by the user.  To force consent, set the `prompt` property to `consent`:

```js
// Generate the url that will be used for the consent dialog.
const authorizeUrl = oAuth2Client.generateAuthUrl({
  // To get a refresh token, you MUST set access_type to `offline`.
  access_type: 'offline',
  // set the appropriate scopes
  scope: 'https://www.googleapis.com/auth/userinfo.profile',
  // A refresh token is only returned the first time the user
  // consents to providing access.  For illustration purposes,
  // setting the prompt to 'consent' will force this consent
  // every time, forcing a refresh_token to be returned.
  prompt: 'consent'
});
```

#### Checking `access_token` information
After obtaining and storing an `access_token`, at a later time you may want to go check the expiration date,
original scopes, or audience for the token.  To get the token info, you can use the `getTokenInfo` method:

```js
// after acquiring an oAuth2Client...
const tokenInfo = await oAuth2Client.getTokenInfo('my-access-token');

// take a look at the scopes originally provisioned for the access token
console.log(tokenInfo.scopes);
```

This method will throw if the token is invalid.

#### OAuth2 with Installed Apps (Electron)
If you're authenticating with OAuth2 from an installed application (like Electron), you may not want to embed your `client_secret` inside of the application sources. To work around this restriction, you can choose the `iOS` application type when creating your OAuth2 credentials in the [Google Developers console](https://console.cloud.google.com/):

![application type](https://user-images.githubusercontent.com/534619/36553844-3f9a863c-17b2-11e8-904a-29f6cd5f807a.png)

If using the `iOS` type, when creating the OAuth2 client you won't need to pass a `client_secret` into the constructor:
```js
const oAuth2Client = new OAuth2Client({
  clientId: <your_client_id>,
  redirectUri: <your_redirect_uri>
});
```

## JSON Web Tokens
The Google Developers Console provides a `.json` file that you can use to configure a JWT auth client and authenticate your requests, for example when using a service account.

``` js
const {JWT} = require('google-auth-library');
const keys = require('./jwt.keys.json');

async function main() {
  const client = new JWT({
    email: keys.client_email,
    key: keys.private_key,
    scopes: ['https://www.googleapis.com/auth/cloud-platform'],
  });
  const url = `https://dns.googleapis.com/dns/v1/projects/${keys.project_id}`;
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
```

The parameters for the JWT auth client including how to use it with a `.pem` file are explained in [samples/jwt.js](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/jwt.js).

#### Loading credentials from environment variables
Instead of loading credentials from a key file, you can also provide them using an environment variable and the `GoogleAuth.fromJSON()` method.  This is particularly convenient for systems that deploy directly from source control (Heroku, App Engine, etc).

Start by exporting your credentials:

```
$ export CREDS='{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "your-private-key-id",
  "private_key": "your-private-key",
  "client_email": "your-client-email",
  "client_id": "your-client-id",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://accounts.google.com/o/oauth2/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "your-cert-url"
}'
```
Now you can create a new client from the credentials:

```js
const {auth} = require('google-auth-library');

// load the environment variable with our keys
const keysEnvVar = process.env['CREDS'];
if (!keysEnvVar) {
  throw new Error('The $CREDS environment variable was not found!');
}
const keys = JSON.parse(keysEnvVar);

async function main() {
  // load the JWT or UserRefreshClient from the keys
  const client = auth.fromJSON(keys);
  client.scopes = ['https://www.googleapis.com/auth/cloud-platform'];
  const url = `https://dns.googleapis.com/dns/v1/projects/${keys.project_id}`;
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
```

#### Using a Proxy
You can set the `HTTPS_PROXY` or `https_proxy` environment variables to proxy HTTPS requests. When `HTTPS_PROXY` or `https_proxy` are set, they will be used to proxy SSL requests that do not have an explicit proxy configuration option present.

## Compute
If your application is running on Google Cloud Platform, you can authenticate using the default service account or by specifying a specific service account.

**Note**: In most cases, you will want to use [Application Default Credentials](#choosing-the-correct-credential-type-automatically).  Direct use of the `Compute` class is for very specific scenarios.

``` js
const {auth, Compute} = require('google-auth-library');

async function main() {
  const client = new Compute({
    // Specifying the service account email is optional.
    serviceAccountEmail: 'my-service-account@example.com'
  });
  const projectId = await auth.getProjectId();
  const url = `https://dns.googleapis.com/dns/v1/projects/${projectId}`;
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
```

## Workload Identity Federation

Using workload identity federation, your application can access Google Cloud resources from Amazon Web Services (AWS), Microsoft Azure or any identity provider that supports OpenID Connect (OIDC).

Traditionally, applications running outside Google Cloud have used service account keys to access Google Cloud resources. Using identity federation, you can allow your workload to impersonate a service account.
This lets you access Google Cloud resources directly, eliminating the maintenance and security burden associated with service account keys.

### Accessing resources from AWS

In order to access Google Cloud resources from Amazon Web Services (AWS), the following requirements are needed:
- A workload identity pool needs to be created.
- AWS needs to be added as an identity provider in the workload identity pool (The Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from AWS).
- Permission to impersonate a service account needs to be granted to the external identity.

Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-aws) on how to configure workload identity federation from AWS.

After configuring the AWS provider to impersonate a service account, a credential configuration file needs to be generated.
Unlike service account credential files, the generated credential configuration file will only contain non-sensitive metadata to instruct the library on how to retrieve external subject tokens and exchange them for service account access tokens.
The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).

To generate the AWS workload identity configuration, run the following command:

```bash
# Generate an AWS configuration file.
gcloud iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AWS_PROVIDER_ID \
    --service-account $SERVICE_ACCOUNT_EMAIL \
    --aws \
    --output-file /path/to/generated/config.json
```

Where the following variables need to be substituted:
- `$PROJECT_NUMBER`: The Google Cloud project number.
- `$POOL_ID`: The workload identity pool ID.
- `$AWS_PROVIDER_ID`: The AWS provider ID.
- `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.

This will generate the configuration file in the specified output file.

You can now [start using the Auth library](#using-external-identities) to call Google Cloud resources from AWS.

### Access resources from Microsoft Azure

In order to access Google Cloud resources from Microsoft Azure, the following requirements are needed:
- A workload identity pool needs to be created.
- Azure needs to be added as an identity provider in the workload identity pool (The Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from Azure).
- The Azure tenant needs to be configured for identity federation.
- Permission to impersonate a service account needs to be granted to the external identity.

Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-azure) on how to configure workload identity federation from Microsoft Azure.

After configuring the Azure provider to impersonate a service account, a credential configuration file needs to be generated.
Unlike service account credential files, the generated credential configuration file will only contain non-sensitive metadata to instruct the library on how to retrieve external subject tokens and exchange them for service account access tokens.
The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).

To generate the Azure workload identity configuration, run the following command:

```bash
# Generate an Azure configuration file.
gcloud iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$AZURE_PROVIDER_ID \
    --service-account $SERVICE_ACCOUNT_EMAIL \
    --azure \
    --output-file /path/to/generated/config.json
```

Where the following variables need to be substituted:
- `$PROJECT_NUMBER`: The Google Cloud project number.
- `$POOL_ID`: The workload identity pool ID.
- `$AZURE_PROVIDER_ID`: The Azure provider ID.
- `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.

This will generate the configuration file in the specified output file.

You can now [start using the Auth library](#using-external-identities) to call Google Cloud resources from Azure.

### Accessing resources from an OIDC identity provider

In order to access Google Cloud resources from an identity provider that supports [OpenID Connect (OIDC)](https://openid.net/connect/), the following requirements are needed:
- A workload identity pool needs to be created.
- An OIDC identity provider needs to be added in the workload identity pool (The Google [organization policy](https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers#restrict) needs to allow federation from the identity provider).
- Permission to impersonate a service account needs to be granted to the external identity.

Follow the detailed [instructions](https://cloud.google.com/iam/docs/access-resources-oidc) on how to configure workload identity federation from an OIDC identity provider.

After configuring the OIDC provider to impersonate a service account, a credential configuration file needs to be generated.
Unlike service account credential files, the generated credential configuration file will only contain non-sensitive metadata to instruct the library on how to retrieve external subject tokens and exchange them for service account access tokens.
The configuration file can be generated by using the [gcloud CLI](https://cloud.google.com/sdk/).

For OIDC providers, the Auth library can retrieve OIDC tokens either from a local file location (file-sourced credentials) or from a local server (URL-sourced credentials).

**File-sourced credentials**
For file-sourced credentials, a background process needs to be continuously refreshing the file location with a new OIDC token prior to expiration.
For tokens with one hour lifetimes, the token needs to be updated in the file every hour. The token can be stored directly as plain text or in JSON format.

To generate a file-sourced OIDC configuration, run the following command:

```bash
# Generate an OIDC configuration file for file-sourced credentials.
gcloud iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$OIDC_PROVIDER_ID \
    --service-account $SERVICE_ACCOUNT_EMAIL \
    --credential-source-file $PATH_TO_OIDC_ID_TOKEN \
    # Optional arguments for file types. Default is "text":
    # --credential-source-type "json" \
    # Optional argument for the field that contains the OIDC credential.
    # This is required for json.
    # --credential-source-field-name "id_token" \
    --output-file /path/to/generated/config.json
```

Where the following variables need to be substituted:
- `$PROJECT_NUMBER`: The Google Cloud project number.
- `$POOL_ID`: The workload identity pool ID.
- `$OIDC_PROVIDER_ID`: The OIDC provider ID.
- `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
- `$PATH_TO_OIDC_ID_TOKEN`: The file path where the OIDC token will be retrieved from. 

This will generate the configuration file in the specified output file.

**URL-sourced credentials**
For URL-sourced credentials, a local server needs to host a GET endpoint to return the OIDC token. The response can be in plain text or JSON.
Additional required request headers can also be specified.

To generate a URL-sourced OIDC workload identity configuration, run the following command:

```bash
# Generate an OIDC configuration file for URL-sourced credentials.
gcloud iam workload-identity-pools create-cred-config \
    projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$OIDC_PROVIDER_ID \
    --service-account $SERVICE_ACCOUNT_EMAIL \
    --credential-source-url $URL_TO_GET_OIDC_TOKEN \
    --credential-source-headers $HEADER_KEY=$HEADER_VALUE \
    # Optional arguments for file types. Default is "text":
    # --credential-source-type "json" \
    # Optional argument for the field that contains the OIDC credential.
    # This is required for json.
    # --credential-source-field-name "id_token" \
    --output-file /path/to/generated/config.json
```

Where the following variables need to be substituted:
- `$PROJECT_NUMBER`: The Google Cloud project number.
- `$POOL_ID`: The workload identity pool ID.
- `$OIDC_PROVIDER_ID`: The OIDC provider ID.
- `$SERVICE_ACCOUNT_EMAIL`: The email of the service account to impersonate.
- `$URL_TO_GET_OIDC_TOKEN`: The URL of the local server endpoint to call to retrieve the OIDC token.
- `$HEADER_KEY` and `$HEADER_VALUE`: The additional header key/value pairs to pass along the GET request to `$URL_TO_GET_OIDC_TOKEN`, e.g. `Metadata-Flavor=Google`.

You can now [start using the Auth library](#using-external-identities) to call Google Cloud resources from an OIDC provider.

### Using External Identities

External identities (AWS, Azure and OIDC-based providers) can be used with `Application Default Credentials`.
In order to use external identities with Application Default Credentials, you need to generate the JSON credentials configuration file for your external identity as described above.
Once generated, store the path to this file in the `GOOGLE_APPLICATION_CREDENTIALS` environment variable.

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/config.json
```

The library can now automatically choose the right type of client and initialize credentials from the context provided in the configuration file.

```js
async function main() {
  const auth = new GoogleAuth({
    scopes: 'https://www.googleapis.com/auth/cloud-platform'
  });
  const client = await auth.getClient();
  const projectId = await auth.getProjectId();
  // List all buckets in a project.
  const url = `https://storage.googleapis.com/storage/v1/b?project=${projectId}`;
  const res = await client.request({ url });
  console.log(res.data);
}
```

When using external identities with Application Default Credentials in Node.js, the `roles/browser` role needs to be granted to the service account.
The `Cloud Resource Manager API` should also be enabled on the project.
This is needed since the library will try to auto-discover the project ID from the current environment using the impersonated credential.
To avoid this requirement, the project ID can be explicitly specified on initialization.

```js
const auth = new GoogleAuth({
  scopes: 'https://www.googleapis.com/auth/cloud-platform',
  // Pass the project ID explicitly to avoid the need to grant `roles/browser` to the service account
  // or enable Cloud Resource Manager API on the project.
  projectId: 'CLOUD_RESOURCE_PROJECT_ID',
});
```

You can also explicitly initialize external account clients using the generated configuration file.

```js
const {ExternalAccountClient} = require('google-auth-library');
const jsonConfig = require('/path/to/config.json');

async function main() {
  const client = ExternalAccountClient.fromJSON(jsonConfig);
  client.scopes = ['https://www.googleapis.com/auth/cloud-platform'];
  // List all buckets in a project.
  const url = `https://storage.googleapis.com/storage/v1/b?project=${projectId}`;
  const res = await client.request({url});
  console.log(res.data);
}
```

## Working with ID Tokens
### Fetching ID Tokens
If your application is running on Cloud Run or Cloud Functions, or using Cloud Identity-Aware
Proxy (IAP), you will need to fetch an ID token to access your application. For
this, use the method `getIdTokenClient` on the `GoogleAuth` client.

For invoking Cloud Run services, your service account will need the
[`Cloud Run Invoker`](https://cloud.google.com/run/docs/authenticating/service-to-service)
IAM permission.

For invoking Cloud Functions, your service account will need the
[`Function Invoker`](https://cloud.google.com/functions/docs/securing/authenticating#function-to-function)
IAM permission.

``` js
// Make a request to a protected Cloud Run service.
const {GoogleAuth} = require('google-auth-library');

async function main() {
  const url = 'https://cloud-run-1234-uc.a.run.app';
  const auth = new GoogleAuth();
  const client = await auth.getIdTokenClient(url);
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
```

A complete example can be found in [`samples/idtokens-serverless.js`](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/idtokens-serverless.js).

For invoking Cloud Identity-Aware Proxy, you will need to pass the Client ID
used when you set up your protected resource as the target audience.

``` js
// Make a request to a protected Cloud Identity-Aware Proxy (IAP) resource
const {GoogleAuth} = require('google-auth-library');

async function main()
  const targetAudience = 'iap-client-id';
  const url = 'https://iap-url.com';
  const auth = new GoogleAuth();
  const client = await auth.getIdTokenClient(targetAudience);
  const res = await client.request({url});
  console.log(res.data);
}

main().catch(console.error);
```

A complete example can be found in [`samples/idtokens-iap.js`](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/idtokens-iap.js).

### Verifying ID Tokens

If you've [secured your IAP app with signed headers](https://cloud.google.com/iap/docs/signed-headers-howto),
you can use this library to verify the IAP header:

```js
const {OAuth2Client} = require('google-auth-library');
// Expected audience for App Engine.
const expectedAudience = `/projects/your-project-number/apps/your-project-id`;
// IAP issuer
const issuers = ['https://cloud.google.com/iap'];
// Verify the token. OAuth2Client throws an Error if verification fails
const oAuth2Client = new OAuth2Client();
const response = await oAuth2Client.getIapCerts();
const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
  idToken,
  response.pubkeys,
  expectedAudience,
  issuers
);

// Print out the info contained in the IAP ID token
console.log(ticket)
```

A complete example can be found in [`samples/verifyIdToken-iap.js`](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/verifyIdToken-iap.js).

## Impersonated Credentials Client

Google Cloud Impersonated credentials used for [Creating short-lived service account credentials](https://cloud.google.com/iam/docs/creating-short-lived-service-account-credentials).

Provides authentication for applications where local credentials impersonates a remote service account using [IAM Credentials API](https://cloud.google.com/iam/docs/reference/credentials/rest).

An Impersonated Credentials Client is instantiated with a `sourceClient`. This
should be an auth client with the "Service Account Token Creator" role (`roles/iam.serviceAccountTokenCreator`). `sourceClient` is used by the Impersonated
Credentials Client to impersonate a target service account with a specified
set of scopes.

### Sample Usage

```javascript
const { GoogleAuth, Impersonated } = require('google-auth-library');
const { SecretManagerServiceClient } = require('@google-cloud/secret-manager');

async function main() {

  // Acquire source credentials:
  const auth = new GoogleAuth();
  const client = await auth.getClient();

  // Impersonate new credentials:
  let targetClient = new Impersonated({
    sourceClient: client,
    targetPrincipal: "impersonated-account@projectID.iam.gserviceaccount.com",
    lifetime: 30,
    delegates: [],
    targetScopes: ["https://www.googleapis.com/auth/cloud-platform"]
  });

  // Get impersonated credentials:
  const authHeaders = await targetClient.getRequestHeaders();
  // Do something with `authHeaders.Authorization`.

  // Use impersonated credentials:
  const url = 'https://www.googleapis.com/storage/v1/b?project=anotherProjectID'
  const resp = targetClient.request({ url });
  for (const bucket of resp.data.items) {
    console.log(bucket.name);
  }

  // Use impersonated credentials with google-cloud client library
  // Note: this works only with certain cloud client libraries utilizing gRPC 
  //    e.g., SecretManager, KMS, AIPlatform
  // will not currently work with libraries using REST, e.g., Storage, Compute
  const smClient = new SecretManagerServiceClient({
    projectId: anotherProjectID,
    auth: {
      getClient: () => targetClient,
    },
  });
  const secretName = 'projects/anotherProjectNumber/secrets/someProjectName/versions/1';
  const [accessResponse] = await smClient.accessSecretVersion({
    name: secretName,
  });

  const responsePayload = accessResponse.payload.data.toString('utf8');
  // Do something with the secret contained in `responsePayload`.
};

main();
```


## Samples

Samples are in the [`samples/`](https://github.com/googleapis/google-auth-library-nodejs/tree/master/samples) directory. Each sample's `README.md` has instructions for running its sample.

| Sample                      | Source Code                       | Try it |
| --------------------------- | --------------------------------- | ------ |
| Adc | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/adc.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/adc.js,samples/README.md) |
| Compute | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/compute.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/compute.js,samples/README.md) |
| Credentials | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/credentials.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/credentials.js,samples/README.md) |
| Headers | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/headers.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/headers.js,samples/README.md) |
| ID Tokens for Identity-Aware Proxy (IAP) | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/idtokens-iap.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/idtokens-iap.js,samples/README.md) |
| ID Tokens for Serverless | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/idtokens-serverless.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/idtokens-serverless.js,samples/README.md) |
| Jwt | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/jwt.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/jwt.js,samples/README.md) |
| Keepalive | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/keepalive.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/keepalive.js,samples/README.md) |
| Keyfile | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/keyfile.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/keyfile.js,samples/README.md) |
| Oauth2-code Verifier | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/oauth2-codeVerifier.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/oauth2-codeVerifier.js,samples/README.md) |
| Oauth2 | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/oauth2.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/oauth2.js,samples/README.md) |
| Sign Blob | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/signBlob.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/signBlob.js,samples/README.md) |
| Verifying ID Tokens from Identity-Aware Proxy (IAP) | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/verifyIdToken-iap.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/verifyIdToken-iap.js,samples/README.md) |
| Verify Id Token | [source code](https://github.com/googleapis/google-auth-library-nodejs/blob/master/samples/verifyIdToken.js) | [![Open in Cloud Shell][shell_img]](https://console.cloud.google.com/cloudshell/open?git_repo=https://github.com/googleapis/google-auth-library-nodejs&page=editor&open_in_editor=samples/verifyIdToken.js,samples/README.md) |



The [Google Auth Library Node.js Client API Reference][client-docs] documentation
also contains samples.

## Supported Node.js Versions

Our client libraries follow the [Node.js release schedule](https://nodejs.org/en/about/releases/).
Libraries are compatible with all current _active_ and _maintenance_ versions of
Node.js.

Client libraries targeting some end-of-life versions of Node.js are available, and
can be installed via npm [dist-tags](https://docs.npmjs.com/cli/dist-tag).
The dist-tags follow the naming convention `legacy-(version)`.

_Legacy Node.js versions are supported as a best effort:_

* Legacy versions will not be tested in continuous integration.
* Some security patches may not be able to be backported.
* Dependencies will not be kept up-to-date, and features will not be backported.

#### Legacy tags available

* `legacy-8`: install client libraries from this dist-tag for versions
  compatible with Node.js 8.

## Versioning

This library follows [Semantic Versioning](http://semver.org/).


This library is considered to be **General Availability (GA)**. This means it
is stable; the code surface will not change in backwards-incompatible ways
unless absolutely necessary (e.g. because of critical security issues) or with
an extensive deprecation period. Issues and requests against **GA** libraries
are addressed with the highest priority.





More Information: [Google Cloud Platform Launch Stages][launch_stages]

[launch_stages]: https://cloud.google.com/terms/launch-stages

## Contributing

Contributions welcome! See the [Contributing Guide](https://github.com/googleapis/google-auth-library-nodejs/blob/master/CONTRIBUTING.md).

Please note that this `README.md`, the `samples/README.md`,
and a variety of configuration files in this repository (including `.nycrc` and `tsconfig.json`)
are generated from a central template. To edit one of these files, make an edit
to its template in this
[directory](https://github.com/googleapis/synthtool/tree/master/synthtool/gcp/templates/node_library).

## License

Apache Version 2.0

See [LICENSE](https://github.com/googleapis/google-auth-library-nodejs/blob/master/LICENSE)

[client-docs]: https://googleapis.dev/nodejs/google-auth-library/latest
[product-docs]: https://cloud.google.com/docs/authentication/
[shell_img]: https://gstatic.com/cloudssh/images/open-btn.png
[projects]: https://console.cloud.google.com/project
[billing]: https://support.google.com/cloud/answer/6293499#enable-billing

[auth]: https://cloud.google.com/docs/authentication/getting-started
