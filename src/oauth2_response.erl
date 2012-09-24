%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012 KIVRA
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
-export([
         new/1
         ,new/2
         ,new/4
         ,new/5
         ,new/6
         ,access_token/1
         ,access_token/2
         ,access_code/1
         ,access_code/2
         ,refresh_token/1
         ,refresh_token/2
         ,resource_owner/1
         ,resource_owner/2
         ,expires_in/1
         ,expires_in/2
         ,scope/1
         ,scope/2
         ,to_proplist/1
        ]).

-record(response, {
          access_token    :: oauth2:token()
          ,access_code    :: oauth2:token()
          ,expires_in     :: oauth2:lifetime()
          ,resource_owner :: term()
          ,scope          :: oauth2:scope()
          ,refresh_token  :: oauth2:token()
          ,token_type = <<"bearer">> :: binary()
         }).

-type response() :: #response{}.
-export_type([
              response/0
             ]).

%%%===================================================================
%%% API functions
%%%===================================================================

new(AccessToken) ->
    #response{access_token = AccessToken}.

new(AccessToken, ExpiresIn) ->
    #response{access_token = AccessToken, expires_in = ExpiresIn}.

new(AccessToken, ExpiresIn, ResOwner, Scope) ->
    #response{access_token = AccessToken,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope}.

new(AccessToken, ExpiresIn, ResOwner, Scope, RefreshToken) ->
    #response{access_token = AccessToken,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope,
              refresh_token = RefreshToken}.

new(_, ExpiresIn, ResOwner, Scope, _, AccessCode) ->
    #response{access_code = AccessCode,
              expires_in = ExpiresIn,
              resource_owner = ResOwner,
              scope = Scope}.

access_token(#response{access_token = undefined}) ->
    {error, not_set};
access_token(#response{access_token = AccessToken}) ->
    {ok, AccessToken}.

access_token(Response, NewAccessToken) ->
    Response#response{access_token = NewAccessToken}.

access_code(#response{access_code = AccessCode}) ->
    {ok, AccessCode}.

access_code(Response, NewAccessCode) ->
    Response#response{access_code = NewAccessCode}.

expires_in(#response{expires_in = undefined}) ->
    {error, not_set};
expires_in(#response{expires_in = ExpiresIn}) ->
    {ok, ExpiresIn}.

expires_in(Response, NewExpiresIn) ->
    Response#response{expires_in = NewExpiresIn}.

scope(#response{scope = undefined}) ->
    {error, not_set};
scope(#response{scope = Scope}) ->
    {ok, Scope}.

scope(Response, NewScope) ->
    Response#response{scope = NewScope}.

refresh_token(#response{refresh_token = undefined}) ->
    {error, not_set};
refresh_token(#response{refresh_token = RefreshToken}) ->
    {ok, RefreshToken}.

refresh_token(Response, NewRefreshToken) ->
    Response#response{refresh_token = NewRefreshToken}.

resource_owner(#response{resource_owner = ResOwner}) ->
    {ok, ResOwner}.

resource_owner(Response, NewResOwner) ->
    Response#response{resource_owner = NewResOwner}.

to_proplist(Response) ->
    Keys = lists:map(fun to_binary/1, record_info(fields, response)),
    Values = tl(tuple_to_list(Response)), %% Head is 'response'!
    [{K, to_binary(V)} || {K , V} <- lists:zip(Keys, Values), V =/= undefined].

%%%===================================================================
%%% Internal functions
%%%===================================================================

to_binary(Atom) when is_atom(Atom) ->
    list_to_binary(atom_to_list(Atom));
to_binary(Integer) when is_integer(Integer) ->
    list_to_binary(integer_to_list(Integer));
to_binary(Binary) when is_binary(Binary) ->
    Binary.
