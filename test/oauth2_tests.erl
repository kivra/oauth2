%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012-2013 KIVRA
%%
%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.
%%
%% ----------------------------------------------------------------------------

-module(oauth2_tests).

-include_lib("eunit/include/eunit.hrl").

%%% Placeholder values that the mock backend will recognize.
-define(USER_NAME,     <<"herp">>).
-define(USER_PASSWORD, <<"derp">>).
-define(USER_SCOPE,    [<<"xyz">>]).
-define(RESOURCE_OWNER, <<"user">>).

-define(CLIENT_ID,     <<"TiaUdYODLOMyLkdaKkqlmhsl9QJ94a">>).
-define(CLIENT_SECRET, <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>).
-define(CLIENT_SCOPE,  <<"abc">>).
-define(CLIENT_URI,    <<"https://no.where/cb">>).

%%%===================================================================
%%% Test cases
%%%===================================================================

bad_authorize_password_test_() ->
    {setup,
        fun start/0,
        fun stop/1,
        fun(_) ->
                [
                 ?_assertMatch({ok, _},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"derp">>,
                                 [<<"xyz">>],
                                 foo_context)),
                 ?_assertMatch({error, invalid_scope},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"derp">>,
                                 <<"bad_scope">>,
                                 foo_context)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_password(
                                 <<"herp">>,
                                 <<"herp">>,
                                 <<"xyz">>,
                                 foo_context)),
                 ?_assertMatch({error, access_denied},
                               oauth2:authorize_password(
                                 <<"derp">>,
                                 <<"derp">>,
                                 <<"xyz">>,
                                 foo_context))
                ]
        end}.

bad_authorize_client_credentials_test_() ->
    {setup,
        fun start/0,
        fun stop/1,
        fun(_) ->
                [
                 ?_assertMatch({error, invalid_client},
                               oauth2:authorize_client_credentials(
                                 <<"XoaUdYODRCMyLkdaKkqlmhsl9QQJ4b">>,
                                 <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>,
                                 <<"abc">>,
                                 foo_context)),
                 ?_assertMatch({error, invalid_scope},
                               oauth2:authorize_client_credentials(
                                 ?CLIENT_ID,
                                 ?CLIENT_SECRET,
                                 <<"bad_scope">>,
                                 foo_context)),
                 ?_assertMatch({error, invalid_client},
                               oauth2:authorize_client_credentials(
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 <<"gggDMAwklAKc9kq5FsLjKrzihCcI123">>,
                                 <<"abc">>,
                                 foo_context)),
                 ?_assertMatch({error, invalid_client},
                                oauth2:authorize_client_credentials(
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 <<"fvfDMAwjlruC9rv5FsLjmyrihCcIKJL">>,
                                 <<"cba">>,
                                 foo_context))
                ]
        end}.

bad_ttl_test_() ->
    {setup,
       fun () ->
                meck:new(oauth2_mock_backend),
                meck:expect(oauth2_mock_backend,
                            authenticate_client,
                            fun(_, _, _) -> {ok, {client, 4711}}
                            end),
                meck:expect(oauth2_mock_backend,
                            resolve_access_code,
                            fun(_, _) -> {ok, [{<<"identity">>, <<"123">>},
                                           {<<"resource_owner">>, <<>>},
                                           {<<"expiry_time">>, 123},
                                           {<<"scope">>, <<>>}]}
                            end),
                meck:expect(oauth2_mock_backend, 
                            revoke_access_code, 
                            fun(_, _) -> ok end),
                meck:expect(oauth2_mock_backend,
                            resolve_access_token,
                            fun(_, _) -> {ok, [{<<"identity">>, <<"123">>},
                                           {<<"resource_owner">>, <<>>},
                                           {<<"expiry_time">>, 123},
                                           {<<"scope">>, <<>>}]}
                            end),
                meck:expect(oauth2_mock_backend, 
                            revoke_access_token, 
                            fun(_, _) -> ok end),
                meck:expect(oauth2_mock_backend,
                            resolve_refresh_token,
                            fun(_, _) -> {ok, [{<<"identity">>, <<"123">>},
                                           {<<"resource_owner">>, <<>>},
                                           {<<"expiry_time">>, 123},
                                           {<<"scope">>, <<>>}]}
                            end),
                meck:expect(oauth2_mock_backend, revoke_refresh_token, fun(_, _) -> ok end),
                ok
        end,
        fun (_) ->
                 meck:unload(oauth2_mock_backend)
        end,
        fun(_) ->
                [
                 ?_assertMatch({error, invalid_grant},
                               oauth2:verify_access_code(
                                 <<"XoaUdYODRCMyLkdaKkqlmhsl9QQJ4b">>,
                                 foo_context)),
                 ?_assertMatch({error, access_denied},
                               oauth2:verify_access_token(
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 foo_context)),
                 ?_assertMatch({error, invalid_grant},
                                oauth2:refresh_access_token(
                                 ?CLIENT_ID,
                                 ?CLIENT_SECRET,
                                 <<"TiaUdYODLOMyLkdaKkqlmdhsl9QJ94a">>,
                                 ?CLIENT_SCOPE,
                                 foo_context))
                ]
        end}.

verify_access_token_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {ok, {foo_context, Authorization}} =
                          oauth2:authorize_client_credentials(
                                         ?CLIENT_ID,
                                         ?CLIENT_SECRET,
                                         ?CLIENT_SCOPE,
                                         foo_context),
                      {ok, {foo_context, Response}} =
                          oauth2:issue_token(Authorization, foo_context),
                      {ok, Token} = oauth2_response:access_token(Response),
                      ?assertMatch( {ok, {foo_context, _}}
                                  , oauth2:verify_access_token( Token
                                                              , foo_context ))
              end,
              ?_assertMatch({error, access_denied},
                 oauth2:verify_access_token(<<"nonexistent_token">>,
                                            foo_context))
             ]
     end}.

bad_access_code_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {error, unauthorized_client} =
                          oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         <<"http://in.val.id">>,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         ?CLIENT_SCOPE,
                                         foo_context),
                      {error, unauthorized_client} =
                          oauth2:authorize_code_request(
                                         <<"XoaUdYODRCMyLkdaKkqlmhsl9QQJ4b">>,
                                         ?CLIENT_URI,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         ?CLIENT_SCOPE,
                                         foo_context),
                      {error, invalid_scope} = oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         <<"bad_scope">>,
                                         foo_context),
                      {error, access_denied} = oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         <<"herp">>,
                                         <<"herp">>,
                                         ?CLIENT_SCOPE,
                                         foo_context),
                      {error, access_denied} = oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         <<"derp">>,
                                         <<"derp">>,
                                         ?CLIENT_SCOPE,
                                         foo_context),
                      ?_assertMatch({error, invalid_grant},
                                    oauth2:verify_access_code(<<"nonexistent_token">>))
              end
             ]
     end}.

verify_access_code_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {ok, {foo_context, Auth}} =
                          oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         ?USER_SCOPE,
                                         foo_context),
                      {ok, {foo_context, Response}} =
                          oauth2:issue_code(Auth, foo_context),
                      {ok, Code} = oauth2_response:access_code(Response),
                      ?assertMatch({ok, {user, 31337}},
                                   oauth2_response:resource_owner(Response)),
                      ?assertMatch({ok, _}, oauth2:verify_access_code(
                                     Code, foo_context)),
                      {ok, {foo_context, Auth2}} =
                          oauth2:authorize_code_grant(
                                         ?CLIENT_ID,
                                         ?CLIENT_SECRET,
                                         Code,
                                         ?CLIENT_URI,
                                         foo_context),
                      {ok, {foo_context, Response2}} =
                          oauth2:issue_token_and_refresh(Auth2, foo_context),
                      {ok, Token} = oauth2_response:access_token(Response2),
                      ?assertMatch({ok, _}, oauth2:verify_access_token(
                                     Token,
                                     foo_context))
              end
             ]
     end}.

bad_refresh_token_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {ok, {foo_context, Auth}} =
                          oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         ?USER_SCOPE,
                                         foo_context),
                      {ok, {foo_context, Response}} =
                          oauth2:issue_code(Auth, foo_context),
                      {ok, Code} = oauth2_response:access_code(Response),
                      {ok, {foo_context, Auth2}} =
                          oauth2:authorize_code_grant(
                                         ?CLIENT_ID,
                                         ?CLIENT_SECRET,
                                         Code,
                                         ?CLIENT_URI,
                                         foo_context),
                      {ok, {foo_context, Res2}} =
                          oauth2:issue_token_and_refresh(Auth2, foo_context),
                      {ok, RefreshToken} = oauth2_response:refresh_token(Res2),
                      ?assertMatch({error, invalid_client},
                                   oauth2:refresh_access_token(
                                     <<"foo">>,
                                     ?CLIENT_SECRET,
                                     RefreshToken,
                                     ?CLIENT_SCOPE,
                                     foo_context)),
                      ?assertMatch({error, invalid_client},
                                   oauth2:refresh_access_token(
                                     ?CLIENT_ID,
                                     <<"foo">>,
                                     RefreshToken,
                                     ?CLIENT_SCOPE,
                                     foo_context)),
                      ?assertMatch({error, invalid_grant},
                                   oauth2:refresh_access_token(
                                     ?CLIENT_ID,
                                     ?CLIENT_SECRET,
                                     <<"foo">>,
                                     ?CLIENT_SCOPE,
                                     foo_context)),
                      ?assertMatch({error, invalid_scope},
                                   oauth2:refresh_access_token(
                                     ?CLIENT_ID,
                                     ?CLIENT_SECRET,
                                     RefreshToken,
                                     <<"foo">>,
                                     foo_context))
              end
             ]
     end}.

verify_refresh_token_test_() ->
    {setup,
     fun start/0,
     fun stop/1,
     fun(_) ->
             [
              fun() ->
                      {ok, {foo_context, Auth}} =
                          oauth2:authorize_code_request(
                                         ?CLIENT_ID,
                                         ?CLIENT_URI,
                                         ?USER_NAME,
                                         ?USER_PASSWORD,
                                         ?USER_SCOPE,
                                         foo_context),
                      {ok, {foo_context, Response}} =
                          oauth2:issue_code(Auth, foo_context),
                      {ok, Code} = oauth2_response:access_code(Response),
                      {ok, {foo_context, Auth2}} =
                          oauth2:authorize_code_grant(
                                         ?CLIENT_ID,
                                         ?CLIENT_SECRET,
                                         Code,
                                         ?CLIENT_URI,
                                         foo_context),
                      {ok, {foo_context, Res2}} =
                          oauth2:issue_token_and_refresh(Auth2, foo_context),
                      {ok, RefreshToken} = oauth2_response:refresh_token(Res2),
                      {ok, _} = oauth2:refresh_access_token(
                                              ?CLIENT_ID,
                                              ?CLIENT_SECRET,
                                              RefreshToken,
                                              ?USER_SCOPE,
                                              foo_context),
                      {ok, Token} = oauth2_response:access_token(Res2),
                      ?assertMatch({ok, _}, oauth2:verify_access_token(
                                     Token,
                                     foo_context))
              end
             ]
     end}.

%%%===================================================================
%%% Setup/teardown
%%%===================================================================

start() ->
    application:set_env(oauth2, backend, oauth2_mock_backend),
    application:set_env(oauth2, expiry_time, 3600),
    oauth2_mock_backend:start(),
    ok.

stop(_State) ->
    oauth2_mock_backend:stop(),
    ok.
