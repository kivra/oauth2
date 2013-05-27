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

-module(oauth2_response).

%% Length of binary data to use for token generation.
-define(TOKEN_LENGTH, 32).

%%% API
-export([new/1]).
-export([new/2]).
-export([new/4]).
-export([new/5]).
-export([new/6]).
-export([access_token/1]).
-export([access_token/2]).
-export([access_code/1]).
-export([access_code/2]).
-export([refresh_token/1]).
-export([refresh_token/2]).
-export([resource_owner/1]).
-export([resource_owner/2]).
-export([expires_in/1]).
-export([expires_in/2]).
-export([scope/1]).
-export([scope/2]).
-export([to_proplist/1]).

-record(response, {
          access_token               :: oauth2:token()
          ,access_code               :: oauth2:token()
          ,expires_in                :: oauth2:lifetime()
          ,resource_owner            :: term()
          ,scope                     :: oauth2:scope()
          ,refresh_token             :: oauth2:token()
          ,token_type = <<"bearer">> :: binary()
         }).

-type response() :: #response{}.
-export_type([response/0]).

%%%===================================================================
%%% API functions
%%%===================================================================

-spec new(AccessToken :: oauth2:token()) -> response().
new(AccessToken) ->
    #response{access_token = AccessToken}.

-spec new(AccessToken, ExpiresIn) -> response() when
    AccessToken :: oauth2:token(),
    ExpiresIn  :: oauth2:lifetime().
new(AccessToken, ExpiresIn) ->
    #response{access_token = AccessToken, expires_in = ExpiresIn}.

-spec new(AccessToken, ExpiresIn, ResOwner, Scope) -> response() when
    AccessToken :: oauth2:token(),
    ExpiresIn   :: oauth2:lifetime(),
    ResOwner    :: term(),
    Scope       :: oauth2:scope().
new(AccessToken, ExpiresIn, ResOwner, Scope) ->
    #response{access_token = AccessToken,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope}.

-spec new(AccessToken, ExpiresIn, ResOwner, Scope, RefreshToken) -> response() when
    AccessToken  :: oauth2:token(),
    ExpiresIn    :: oauth2:lifetime(),
    ResOwner     :: term(),
    Scope        :: oauth2:scope(),
    RefreshToken :: oauth2:token().
new(AccessToken, ExpiresIn, ResOwner, Scope, RefreshToken) ->
    #response{access_token = AccessToken,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope,
              refresh_token = RefreshToken}.

-spec new(_AccessToken, ExpiresIn, ResOwner, Scope, _RefreshToken, AccessCode) -> response() when
    _AccessToken  :: oauth2:token(),
    ExpiresIn     :: oauth2:lifetime(),
    ResOwner      :: term(),
    Scope         :: oauth2:scope(),
    _RefreshToken :: oauth2:token(),
    AccessCode    :: oauth2:token().
new(_AccessToken, ExpiresIn, ResOwner, Scope, _RefreshToken, AccessCode) ->
    #response{access_code = AccessCode,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope}.

-spec access_token(response()) -> {ok, AccessToken} | {error, not_set} when
    AccessToken :: oauth2:token().
access_token(#response{access_token = undefined}) ->
    {error, not_set};
access_token(#response{access_token = AccessToken}) ->
    {ok, AccessToken}.

-spec access_token(response(), NewAccessToken) -> response() when
    NewAccessToken :: oauth2:token().
access_token(Response, NewAccessToken) ->
    Response#response{access_token = NewAccessToken}.

-spec access_code(response())  -> {ok, AccessCode} | {error, not_set} when
    AccessCode :: oauth2:token().
access_code(#response{access_code = undefined}) ->
    {error, not_set};
access_code(#response{access_code = AccessCode}) ->
    {ok, AccessCode}.

-spec access_code(response(), NewAccessCode) -> response() when
    NewAccessCode :: oauth2:token().
access_code(Response, NewAccessCode) ->
    Response#response{access_code = NewAccessCode}.

-spec expires_in(response()) -> {ok, ExpiresIn} | {error, not_set} when
    ExpiresIn :: oauth2:lifetime().
expires_in(#response{expires_in = undefined}) ->
    {error, not_set};
expires_in(#response{expires_in = ExpiresIn}) ->
    {ok, ExpiresIn}.

-spec expires_in(response(), NewExpiresIn) -> response() when
    NewExpiresIn :: oauth2:lifetime().
expires_in(Response, NewExpiresIn) ->
    Response#response{expires_in = NewExpiresIn}.

-spec scope(response()) -> {ok, Scope} | {error, not_set} when
    Scope :: oauth2:scope().
scope(#response{scope = undefined}) ->
    {error, not_set};
scope(#response{scope = Scope}) ->
    {ok, Scope}.

-spec scope(response(), NewScope) -> response() when
    NewScope :: oauth2:scope().
scope(Response, NewScope) ->
    Response#response{scope = NewScope}.

-spec refresh_token(response()) -> {ok, RefreshToken} | {error, not_set} when
    RefreshToken :: oauth2:token().
refresh_token(#response{refresh_token = undefined}) ->
    {error, not_set};
refresh_token(#response{refresh_token = RefreshToken}) ->
    {ok, RefreshToken}.

-spec refresh_token(response(), NewRefreshToken) -> response() when
    NewRefreshToken :: oauth2:token().
refresh_token(Response, NewRefreshToken) ->
    Response#response{refresh_token = NewRefreshToken}.

-spec resource_owner(response()) -> {ok, ResOwner} when
    ResOwner :: term().
resource_owner(#response{resource_owner = ResOwner}) ->
    {ok, ResOwner}.

-spec resource_owner(response(), NewResOwner) -> response() when
    NewResOwner :: term().
resource_owner(Response, NewResOwner) ->
    Response#response{resource_owner = NewResOwner}.

-spec to_proplist(response()) -> oauth2:proplist(binary(), binary()).
to_proplist(Response) ->
    Keys = lists:map(fun to_binary/1, record_info(fields, response)),
    Values = tl(tuple_to_list(Response)), %% Head is 'response'!
    [{K, to_binary(V)} || {K , V} <- lists:zip(Keys, Values), V =/= undefined].

%%%===================================================================
%%% Internal functions
%%%===================================================================

to_binary(Binary) when is_binary(Binary) ->
    Binary;
to_binary(List) when is_list(List) ->
    to_binary(list_to_binary(List));
to_binary(Atom) when is_atom(Atom) ->
    to_binary(atom_to_list(Atom));
to_binary(Float) when is_float(Float) ->
    to_binary(float_to_list(Float));
to_binary(Integer) when is_integer(Integer) ->
    to_binary(integer_to_list(Integer));
to_binary(Term) ->
    to_binary(term_to_binary(Term)).
