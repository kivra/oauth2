%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012-2014 Kivra
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

-module(oauth2_response_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(ACCESS,  <<"9bX9iFUOsXbM12OOjfDW175IXXOELp6K">>).
-define(REFRESH, <<"JVs3ZFQJBIdduJdhhWOoAt2B3qEKcHEo">>).
-define(CODE,    <<"Lz7Z24cKSQ28z8kem01ZP9c0aE3TEbGl">>).
-define(RESOURCE_OWNER, <<"user">>).
-define(EXPIRY,  3600).
-define(SCOPE,   <<"herp derp">>).
-define(TOKEN_TYPE, <<"bearer">>).


%%%===================================================================
%%% Test cases
%%%===================================================================

proper_type_spec_test_() ->
    {timeout, 1200, [{?LINE,
                      fun() -> proper:check_specs(oauth2_response,
                                                  [{to_file, user}]) end}]}.

new_1_test_() ->
    {setup,
     fun() -> oauth2_response:new(?ACCESS) end,
     fun(_) -> ok end,
     fun(Response) ->
             [
              ?_assertEqual({ok, ?ACCESS}, oauth2_response:access_token(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:expires_in(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:scope(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:refresh_token(Response))
             ]
     end}.

new_2_test_() ->
    {setup,
     fun() -> oauth2_response:new(?ACCESS, ?EXPIRY) end,
     fun(_) -> ok end,
     fun(Response) ->
             [
              ?_assertEqual({ok, ?ACCESS}, oauth2_response:access_token(Response)),
              ?_assertEqual({ok, ?EXPIRY}, oauth2_response:expires_in(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:scope(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:refresh_token(Response))
             ]
     end}.

new_4_test_() ->
    {setup,
     fun() -> oauth2_response:new(?ACCESS, ?EXPIRY, ?RESOURCE_OWNER, ?SCOPE) end,
     fun(_) -> ok end,
     fun(Response) ->
             [
              ?_assertEqual({ok, ?ACCESS}, oauth2_response:access_token(Response)),
              ?_assertEqual({ok, ?EXPIRY}, oauth2_response:expires_in(Response)),
              ?_assertEqual({ok, ?SCOPE}, oauth2_response:scope(Response)),
              ?_assertMatch({error, not_set}, oauth2_response:refresh_token(Response))
             ]
     end}.

new_5_test_() ->
    {setup,
     fun() -> oauth2_response:new(?ACCESS, ?EXPIRY, ?RESOURCE_OWNER, ?SCOPE, ?REFRESH, ?EXPIRY) end,
     fun(_) -> ok end,
     fun(Response) ->
             [
              ?_assertEqual({ok, ?ACCESS}, oauth2_response:access_token(Response)),
              ?_assertEqual({ok, ?EXPIRY}, oauth2_response:expires_in(Response)),
              ?_assertEqual({ok, ?SCOPE}, oauth2_response:scope(Response)),
              ?_assertEqual({ok, ?REFRESH}, oauth2_response:refresh_token(Response))
             ]
     end}.


new_6_test_() ->
    {setup,
     fun() -> oauth2_response:new(?ACCESS, ?EXPIRY, ?RESOURCE_OWNER, ?SCOPE, ?REFRESH, ?EXPIRY, ?CODE) end,
     fun(_) -> ok end,
     fun(Response) ->
             [
              ?_assertEqual({error, not_set}, oauth2_response:access_token(Response)),
              ?_assertEqual({ok, ?EXPIRY}, oauth2_response:expires_in(Response)),
              ?_assertEqual({ok, ?SCOPE}, oauth2_response:scope(Response)),
              ?_assertEqual({error, not_set}, oauth2_response:refresh_token(Response)),
              ?_assertEqual({ok, ?CODE}, oauth2_response:access_code(Response))
             ]
     end}.


access_token_test() ->
    ?assertEqual({ok, ?REFRESH},
                 oauth2_response:access_token(
                   oauth2_response:access_token(
                     oauth2_response:new(?ACCESS),
                     ?REFRESH))).

access_code_test() ->
    ?assertEqual({ok, ?CODE},
                 oauth2_response:access_code(
                   oauth2_response:access_code(
                     oauth2_response:new([], [], [], [], [], ?CODE),
                     ?CODE))).

expires_in_test() ->
    ?assertEqual({ok, ?EXPIRY},
                 oauth2_response:expires_in(
                   oauth2_response:expires_in(
                   oauth2_response:new(?ACCESS),
                     ?EXPIRY))).

scope_test() ->
    ?assertEqual({ok, ?SCOPE},
                 oauth2_response:scope(
                   oauth2_response:scope(
                     oauth2_response:new(?ACCESS),
                     ?SCOPE))).

refresh_token_test() ->
    ?assertEqual({ok, ?REFRESH},
                 oauth2_response:refresh_token(
                   oauth2_response:refresh_token(
                     oauth2_response:new(?ACCESS),
                     ?REFRESH))).

resource_owner_test() ->
    ?assertEqual({ok, ?RESOURCE_OWNER},
                 oauth2_response:resource_owner(
                   oauth2_response:resource_owner(
                     oauth2_response:new(?ACCESS),
                     ?RESOURCE_OWNER))).

token_type_test() ->
    ?assertEqual({ok, ?TOKEN_TYPE},
                 oauth2_response:token_type(oauth2_response:new(?ACCESS))).

to_proplist_test() ->
    Property = ?FORALL(
        {AccessToken, Expiry, ResourceOwner, Scope, RefreshToken, RefreshExpiry},
        {non_empty(oauth2:token()), oauth2:lifetime(), binary(), oauth2:scope(), non_empty(oauth2:token()), oauth2:lifetime()},
    begin
        Response = oauth2_response:new(AccessToken, Expiry, ResourceOwner, Scope, RefreshToken, RefreshExpiry),
        [
         {<<"access_token">>, AccessToken},
         {<<"expires_in">>, Expiry},
         {<<"resource_owner">>, ResourceOwner},
         {<<"scope">>, scope_to_binary(Scope)},
         {<<"refresh_token">>, RefreshToken},
         {<<"refresh_token_expires_in">>, RefreshExpiry},
         {<<"token_type">>, <<"bearer">>}
        ] =:= oauth2_response:to_proplist(Response)
    end),
    ?assert(proper:quickcheck(Property, [{to_file, user}])).

-ifndef(pre17).
to_map_test() ->
    Property = ?FORALL(
        {AccessToken, Expiry, ResourceOwner, Scope, RefreshToken, RefreshExpiry},
        {non_empty(oauth2:token()), oauth2:lifetime(), binary(), oauth2:scope(), non_empty(oauth2:token()), oauth2:lifetime()},
    begin
        Response = oauth2_response:new(AccessToken, Expiry, ResourceOwner, Scope, RefreshToken, RefreshExpiry),
        #{
          <<"access_token">> => AccessToken,
          <<"expires_in">> => Expiry,
          <<"resource_owner">> => ResourceOwner,
          <<"scope">> => scope_to_binary(Scope),
          <<"refresh_token">> => RefreshToken,
          <<"refresh_token_expires_in">> => RefreshExpiry,
          <<"token_type">> => <<"bearer">>
        } =:= oauth2_response:to_map(Response)
    end),
    ?assert(proper:quickcheck(Property, [{to_file, user}])).
-endif.

%%%===================================================================
%%% Helpers
%%%===================================================================

scope_to_binary(Binary) when is_binary(Binary) ->
    Binary;
scope_to_binary([]) ->
    <<>>;
scope_to_binary([Binary]) when is_binary(Binary) ->
    Binary;
scope_to_binary([BinaryHead | Tail]) when is_binary(BinaryHead) ->
    <<BinaryHead/binary, " ", (scope_to_binary(Tail))/binary>>.
