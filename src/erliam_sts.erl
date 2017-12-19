%%% @copyright (C) 2017, AdRoll
%%% @doc
%%%
%%%     Support obtaining session tokens from STS using long-term credentials or
%%%     assuming an IAM role.
%%%
%%% @end
%%% Created :  2 Jun 2017 by Mike Watters <mike.watters@adroll.com>

-module(erliam_sts).

-export([
         get_session_token/1,
         assume_role/3
]).

-define(STS_HOST, erliam_config:g(sts_host, "sts.amazonaws.com")).
-define(STS_REGION, erliam_config:g(sts_region, "us-east-1")).
-define(STS_TIMEOUT, 30000).

%%%% API

%% @doc Assume the IAM role given by the ARN using the specified session name.
%% Note that this function is mutually exclusive to using a session token.
%%
%% There is currently no provision for supporting multi-factor authentication
%% (MFA) parameters.
assume_role(Credentials, RoleArn, RoleSessionName) ->
    Query = #{"Action" => "AssumeRole",
              "Version" => "2011-06-15",
              "RoleSessionName" => RoleSessionName,
              "RoleArn" => RoleArn},
    dispatch_request(Credentials, Query).

%% @doc Get AWS credentials from the token service. Note that this function
%% is mutually exclusive to assuming a role using an IAM ARN.
get_session_token(Credentials) ->
    Query = #{"Action" => "GetSessionToken",
              "Version" => "2011-06-15"},
    dispatch_request(Credentials, Query).


%%%% INTERNAL FUNCTIONS

dispatch_request(Credentials, Query) ->
    Host = ?STS_HOST,
    Headers = [{"Accept", "text/xml"}] ++
        awsv4:headers(Credentials, #{service => "sts",
                                     region => ?STS_REGION,
                                     query_params => Query,
                                     host => Host}),
    Url = "https://" ++ Host ++ "?" ++ awsv4:canonical_query(Query),
    decode_response(httpc:request(get, {Url, Headers},
                                  [{timeout, ?STS_TIMEOUT}],
                                  [{body_format, binary}],
                                  erliam:httpc_profile()), get_keypath(Query)).

get_keypath(#{"Action" := "GetSessionToken"}) ->
    ['GetSessionTokenResponse', 'GetSessionTokenResult', 'Credentials'];
get_keypath(#{"Action" := "AssumeRole"}) ->
    ['AssumeRoleResponse', 'AssumeRoleResult', 'Credentials'];
get_keypath(Other) ->
    {error, {bad_keypath_query, Other}}.

decode_response({ok, {{_, 200, _}, Headers, Body}}, KeyPath) ->
    case erliam_util:mime_type(Headers) of
        "text/xml" ->
            decode_credentials([erliam_xml:parse(Body)], KeyPath);
        _ ->
            {error, unacceptable_response}
    end;

decode_response({ok, {{_, 406, _}, _, _}}, _KeyPath) ->
    %% the server respected our accept header and could not produce a response with any of
    %% the requested mime types:
    {error, unacceptable_response};

decode_response({ok, {{_, Code, Status}, _, _}}, _KeyPath) ->
    {error, {bad_response, {Code, Status}}};

decode_response({error, _} = Error, _KeyPath) ->
    Error.

decode_credentials(Plist, KeyPath) ->
    case lists:foldl(fun (E, A) when is_list(A) ->
                             erliam_util:getkey(E, A);
                         (_, _) ->
                             undefined
                     end, Plist, KeyPath) of
        CredentialPlist when is_list(CredentialPlist) ->
            awsv4:credentials_from_plist(convert_credential_plist(CredentialPlist));
        _ ->
            {error, {bad_result, Plist}}
    end.

convert_credential_plist(Plist) ->
    KeyMap = [{'AccessKeyId', access_key_id},
              {'SecretAccessKey', secret_access_key},
              {'Expiration', expiration},
              {'SessionToken', token}],
    [{erliam_util:getkey(K, KeyMap), binary_to_list(V)}
     || {K, V} <- Plist].
