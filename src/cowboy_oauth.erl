-module(cowboy_oauth).

-include("cowboy_oauth.hrl").

-export([
         redirected_authorization_code_response/4,
         redirected_access_token_response/7,
         redirected_error_response/4,
         json_error_response/2,
         scope_to_list/1,
         list_to_scope/1,
         decode_grant_type/1,
         decode_response_type/1,
         access_token_response/5,
         access_refresh_token_response/6,
         redirected_2fa_request/7,
         allowed/2,
         get_token/1,
         resolve_bearer/1
         ]).

-define(TOKEN_LIFETIME, 120). %% two minutes

allowed(undefined, _Permission) ->
    false;
allowed({User, ScopeP}, Permission) ->
    libsnarlmatch:test_perms(Permission, ScopeP)
        andalso libsnarl:allowed(User, Permission).

get_token(Req) ->
    case cowboy_req:parse_header(<<"authorization">>, Req) of
        {ok, {<<"bearer">>, Bearer}, Req1} ->
            {resolve_bearer(Bearer), Req1};
        {ok, _, Req1} ->
            {undefined, Req1}
    end.

resolve_bearer(Bearer) ->
    case ls_oauth:verify_access_token(Bearer) of
        {ok, Context} ->
            case {proplists:get_value(<<"resource_owner">>, Context),
                  proplists:get_value(<<"scope">>, Context)} of
                {undefined, _} ->
                    undefined;
                {UUID, Scope} ->
                    SPerms = scope_perms(ls_oauth:scope(Scope), []),
                    {UUID, SPerms}
            end;
        E ->
            lager:warning("[oauth] could not resolve bearer: ~p", [E]),
            undefined
    end.

scope_perms([], Acc) ->
    lists:usort(Acc);
scope_perms([{_, _, _, Perms} | R], Acc) ->
    scope_perms(R, Acc ++ Perms).


redirected_2fa_request(Type, UUID, Authorization, State, URI, RedirectBase, Req) ->
    Lifetime = application:get_env(cowboy_oauth, mfa_token_lifetime, ?TOKEN_LIFETIME),
    {ok, Code} = ls_token:add(Lifetime, {Type, UUID, Authorization, URI}),
    Params = [{<<"response_type">>, Type}, {<<"fifo_otp_token">>, Code},
              {<<"state">>, State}, {<<"redirect_uri">>, URI}],
    Location = <<RedirectBase/binary, "?", (cow_qs:qs(Params))/binary>>,
    cowboy_req:reply(302, [{<<"location">>, Location}], <<>>, Req).

redirected_authorization_code_response(Uri, Code, State, Req) ->
    Params = [{<<"code">>, Code}, {<<"state">>, State}],
    Location = <<Uri/binary, "?", (cow_qs:qs(Params))/binary>>,
    cowboy_req:reply(302, [{<<"location">>, Location}], <<>>, Req).

json_error_response(Error, Req) ->
    H = [{<<"content-type">>, <<"application/json">>}],
    ErrorJSON = build_error(Error),
    ErrorBin = jsx:encode(ErrorJSON),
    {Code, H1} =
        case Error of
            invalid_client ->
                {401, [{<<"WWW-Authenticate">>, <<"Basic">>} | H]};
            unauthorized_client ->
                {403, H};
            _Other ->
                {400, H}
    end,
    cowboy_req:reply(Code, H1, ErrorBin, Req).

redirected_error_response(Uri, Error, undefined, Req) ->
    Params = [{<<"error">>, error_bin(Error)}],
    Location = <<Uri/binary, "?", (cow_qs:qs(Params))/binary>>,
    cowboy_req:reply(302, [{<<"location">>, Location}], <<>>, Req);

redirected_error_response(Uri, Error, State, Req) ->
    Params = [{<<"error">>, error_bin(Error)}, {<<"state">>, State}],
    Location = <<Uri/binary, "?", (cow_qs:qs(Params))/binary>>,
    cowboy_req:reply(302, [{<<"location">>, Location}], <<>>, Req).

error_bin({error, E}) when is_atom(E) ->
    atom_to_binary(E, utf8);
error_bin(E) when is_atom(E) ->
    atom_to_binary(E, utf8);
error_bin(_) ->
    <<"argh!">>.



access_refresh_token_response(AccessToken, Type, Expires, RefreshToken, Scope,
                              Req) ->
    JSON = [{<<"access_token">>, AccessToken},
            {<<"token_type">>, Type},
            {<<"expires_in">>, Expires},
            {<<"refresh_token">>, RefreshToken},
            {<<"scope">>, Scope}],
    cowboy_req:reply(200, [], jsx:encode(JSON), Req).


redirected_access_token_response(Uri, Token, Type, Expires, Scope,
                                 State, Req) ->
    Params = [{<<"access_token">>, Token},
              {<<"token_type">>, Type},
              {<<"expires_in">>, Expires},
              {<<"state">>, State},
              {<<"scope">>, Scope}],
    Location = <<Uri/binary, "#", (cow_qs:qs(Params))/binary>>,
    cowboy_req:reply(302, [{<<"location">>, Location}], <<>>, Req).

access_token_response(AccessToken, Type, Expires, Scope, Req) ->
    JSON = [{<<"access_token">>, AccessToken},
            {<<"token_type">>, Type},
            {<<"expires_in">>, Expires},
            {<<"scope">>, Scope}],
    cowboy_req:reply(200, [{<<"cache-control">>, <<"no-store">>}],
                     jsx:encode(JSON), Req).


build_error(Error) ->
    {ErrorName, Desc} = errod_description(Error),
    [{<<"error">>, ErrorName},
     {<<"error_description">>, Desc}].


errod_description(invalid_request) ->
    {<<"invalid_request">>,
     <<"The request is missing a required parameter, includes an ",
       "invalid parameter value, includes a parameter more than ",
       "once, or is otherwise malformed.">>};

errod_description(invalid_client) ->
    {<<"invalid_client">>,
     <<"Client authentication failed (e.g., unknown client, no ",
       "client authentication included, or unsupported ",
       "authentication method).  The authorization server MAY ",
       "return an HTTP 401 (Unauthorized) status code to indicate ",
       "which HTTP authentication schemes are supported.  If the ",
       "client attempted to authenticate via the \"Authorization\" ",
       "request header field, the authorization server MUST ",
       "respond with an HTTP 401 (Unauthorized) status code and ",
       "include the \"WWW-Authenticate\" response header field ",
       "matching the authentication scheme used by the client.">>};

errod_description(unauthorized_client) ->
    {<<"unauthorized_client">>,
     <<"The client is not authorized to request an authorization ",
       "code using this method.">>};

errod_description(access_denied) ->
    {<<"access_denied">>,
     <<"The resource owner or authorization server denied the ",
       "request.">>};

errod_description(unsupported_response_type) ->
    {<<"unsupported_response_type">>,
     <<"The authorization server does not support obtaining an ",
       "authorization code using this method.">>};

errod_description(invalid_scope) ->
    {<<"invalid_scope">>,
     <<"The requested scope is invalid, unknown, or malformed.">>};

errod_description(server_error) ->
    {<<"server_error">>,
     <<"The authorization server encountered an unexpected ",
       "condition that prevented it from fulfilling the request. ",
       "(This error code is needed because a 500 Internal Server ",
       "Error HTTP status code cannot be returned to the client ",
       "via an HTTP redirect.)">>};

errod_description(temporarily_unavailable) ->
    {<<"temporarily_unavailable">>,
     <<"The authorization server is currently unable to handle ",
       "the request due to a temporary overloading or maintenance ",
       "of the server.  (This error code is needed because a 503 ",
       "Service Unavailable HTTP status code cannot be returned ",
       "to the client via an HTTP redirect.)">>};

errod_description(Error) ->
    {<<"server_error">>,
     <<"An unknown error occourd: ", (error_bin(Error))/binary>>}.

decode_grant_type(<<"password">>) ->
    password;
decode_grant_type(<<"client_credentials">>) ->
    client_credentials;
decode_grant_type(<<"authorization_code">>) ->
    authorization_code;
decode_grant_type(<<"refresh_token">>) ->
    refresh_token;
%% TODO: 4.5 Extension grants
decode_grant_type(_) ->
    unknown_grant_type.

decode_response_type(<<"code">>) ->
    code;
decode_response_type(<<"token">>) ->
    token;
decode_response_type(_) ->
    unknown_response_type.

scope_to_list(undefined) ->
    undefined;

scope_to_list(Scope) ->
    list_to_binary(string:join([binary_to_list(S) || S <- Scope], " ")).

list_to_scope(undefined) ->
    undefined;
list_to_scope(Scope) ->
    ScopeS = binary_to_list(Scope),
    [list_to_binary(X) || X <- string:tokens(ScopeS, " ")].
