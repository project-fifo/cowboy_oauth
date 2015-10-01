This library contains cowboy handlers that are compatible to the OAuth2 specs and interface with snarl as a backend.

It includes additional support for 2FA with YubiKeys as a custom extension, that however is not needed and can be skipped.

An example of including the endpoints can be found below. Please note that the token endpoint has one parameter that is the base URL for the 2FA auth (can be left out if 2FA is not used).

```erlang
{<<"/api/:version/oauth/token">>,
 cowboy_oauth_token, []},
{<<"/api/:version/oauth/auth">>,
 cowboy_oauth_auth, [<<"/api/0.2.0/oauth/2fa">>]},
{<<"/api/:version/oauth/2fa">>,
 cowboy_oauth_2fa, []}
```

In addition to the handlers it provides three helper functions:


* `cowboy_oauth:get_token/1` which takes a cowboy request, extracts the bearer token and resolves it to the information needed for testing permissions and a new request object (`{AuthData, Req1}`).
```erlang
%%
{AuthData, Req1} = cowboy_oauth:get_token(Req),
%%...
```

* `cowboy_oauth:resolve_bearer/1` wich resolves a raw bearer token (if it is not passed via the Authentication header) into the input required for `cowboy_oauth:allowed/2`

```erlang
%%
AuthData = cowboy_oauth:resolve_bearer(<<"grizly bearer token">>),
%%...
```

* `cowboy_oauth:allowed/2` which takes the response of the other two functions as a first argument and tests if it has a permission passed as the second argument. It will take the scope into account!
  
```erlang
%%
true = cowboy_oauth:allowed(AuthData, [<<"cloud">>, <<"vms">>, <<"create">>]),
%%...
```

The OAuth2 forms used can be configured via the environment parameters `oauth_form` and `oauth_2fa_form` defaults for the `.dtl` files can be found in the `templates` directory.

# Interacting

The following examples are based on the CURL commands from [oauth2_webmachine](https://github.com/IvanMartinez/oauth2_webmachine)

The examples use the following conventions:

* Auth endpoint - `http://192.168.1.41/api/0.2.0/oauth/auth`
* Token endpoint - `http://192.168.1.41/api/0.2.0/oauth/token`
* User login - `admin`
* User password - `admin`
* Client ID - `test`
* Client Secret `test`
* Client redirect URI - `http://localhost`

### Authorization Code Grant

#### CURL

```bash
curl -v -X POST \
  http://192.168.1.41/api/0.2.0/oauth/auth -d \
  "response_type=code&client_id=test&redirect_uri=http://localhost&scope=*&state=foo&username=admin&password=admin"
```

The server responds with a HTTP 302 status, and the authorization code is in the Location field of the header

```http
location: http://localhost?code=6nZNUuYeBM7dfD0k45VF8ZnVKTZJRe2C&state=foo
```

Use that code to request an access token

```bash
curl -v -X POST http://192.168.1.41/api/0.2.0/oauth/token -d \
"grant_type=authorization_code&client_id=test&client_secret=test&redirect_uri=http://localhost&code=6nZNUuYeBM7dfD0k45VF8ZnVKTZJRe2C"

```

The response will look like this:

```json
{
    "access_token": "Ebaz7zB51OPXnmOlVDnKRhv9Ig9kKW2V",
    "token_type": "bearer",
    "expires_in": 86400,
    "refresh_token": "Qpxr7bOaDA4NUloYc9XYWmS16QAio3Dr",
    "scope": [
        "*"
    ]
}
```
#### HTTPie

```bash
http --form \
  POST http://192.168.1.41/api/0.2.0/oauth/auth \
  response_type=code client_id=test \
  redirect_uri=http://localhost \
  scope=* \
  state=foo \
  username=admin \
  password=admin
```

The server responds with a HTTP 302 status, and the authorization code is in the Location field of the header

```http
location: http://localhost?code=ZKSytwIzw5VCE3dcTD4A7wgE3stg4dX4&state=foo
```

Use that code to request an access token

```bash
http --form \
  POST http://192.168.1.41/api/0.2.0/oauth/token \
  grant_type=authorization_code \
  client_id=test \
  client_secret=test \
  redirect_uri=http://localhost \
  code=ZKSytwIzw5VCE3dcTD4A7wgE3stg4dX4
```

The response will look like this:

```json
{
    "access_token": "AehTS7wrcTp4JY1CZchsXbGyZdmBUvk2",
    "expires_in": 86400,
    "refresh_token": "gcSwNN369G2Ks8cet2CQTzYdlebpQtkD",
    "scope": [
        "*"
    ],
    "token_type": "bearer"
}
```

### Implicit Grant


#### CURL
    
```bash
curl -v -X POST http://192.168.1.41/api/0.2.0/oauth/auth -d \
  "response_type=token&client_id=test&redirect_uri=http://localhost&scope=*&state=foo&username=admin&password=admin"
```

The server responds with a HTTP 302 status, and the access token is in the Location field of the header

```http
location: http://localhost#access_token=W9QNN10ZdFNSt7kDcbINtBYWb7brNXqE&token_type=bearer&expires_in=86400&state=foo&scope=%2A
```

#### HTTPie

```bash
http --form \
  POST http://192.168.1.41/api/0.2.0/oauth/auth \
  response_type=token \
  client_id=test \
  redirect_uri=http://localhost \
  scope=* \
  state=foo \
  username=admin \
  password=admin
```

The server responds with a HTTP 302 status, and the access token is in the Location field of the header

```http
location: http://localhost#access_token=oCuag0G5VzMZ4AydyYfe9wcjqe9JnqKw&token_type=bearer&expires_in=86400&state=foo&scope=%2A
```

### Resource Owner Password Credentials Grant

#### CURL

Send an access token request with

```bash
curl -v -X POST http://192.168.1.41/api/0.2.0/oauth/token -d \
"grant_type=password&username=admin&password=admin&scope=*"
```

The response will look like this:

```json
{
    "access_token": "JaYoUbKFdU6hCJBqzr4iayM63fvPk0Wk",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```

#### HTTPie

```bash
http --form POST http://192.168.1.41/api/0.2.0/oauth/token \
  grant_type=password \
  username=admin \
  password=admin \
  scope=*
```

The response will look like this:

```json
{
    "access_token": "JaYoUbKFdU6hCJBqzr4iayM63fvPk0Wk",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```

### Client Credentials Grant

Send an access token request with

#### CURL

```bash
curl -v -X POST http://192.168.1.41/api/0.2.0/oauth/token -d \
"grant_type=client_credentials&client_id=test&client_secret=test&scope=*"
```

The response will look like this:

```json
{
    "access_token": "8bNpl12bdnup9oUCfpR7UXOI0EJ2dGty",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```

#### HTTPie

```bash
http --form POST http://192.168.1.41/api/0.2.0/oauth/token \
  grant_type=client_credentials \
  client_id=test \
  client_secret=test \
  scope=*
```

The response will look like this:

```json
{
    "access_token": "8bNpl12bdnup9oUCfpR7UXOI0EJ2dGty",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```

### Refreshing an Access Token

If the Authorization Code Grant flow is performed succesfully, the response to the final request should include a refresh token as follows

    "refresh_token":"gcSwNN369G2Ks8cet2CQTzYdlebpQtkD"

Obtain a new access token from the refresh token with 

#### CURL

```bash
curl -v -X POST http://192.168.1.41/api/0.2.0/oauth/token -d \
"grant_type=refresh_token&client_id=test&client_secret=test&refresh_token=gcSwNN369G2Ks8cet2CQTzYdlebpQtkD&scope=*"
```

The response will look like this:

```json
{
    "access_token": "fNsfwTV5lgvF1cWdTiGIphwUUsbI4mSU",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```

#### HTTPie
```bash
http --form POST http://192.168.1.41/api/0.2.0/oauth/token \
  grant_type=refresh_token \
  client_id=test \
  client_secret=test \
  refresh_token=gcSwNN369G2Ks8cet2CQTzYdlebpQtkD \
  scope=*
```


The response will look like this:

```json
{
    "access_token": "fNsfwTV5lgvF1cWdTiGIphwUUsbI4mSU",
    "expires_in": 86400,
    "scope": "*",
    "token_type": "bearer"
}
```
