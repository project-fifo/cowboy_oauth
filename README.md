This library contains cowboy handlers that are compatible to the OAuth2 specs and interface with snarl as a backend.

It includes additional support for 2FA with YubiKeys as a custom extension, that however is not needed and can be skipped.

An example of including the endpoints can be found below. Please note that the token endpoint has one parameter that is the base URL for the 2FA auth (can be left out if 2FA is not used).

```erlang
     {<<"/api/:version/oauth/token">>,
      cowboy_oauth_token, [<<"/api/0.2.0/oauth/2fa">>]},
     {<<"/api/:version/oauth/auth">>,
      cowboy_oauth_auth, []},
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

