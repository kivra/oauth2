%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2012-2014 Kivra
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc Erlang OAuth 2.0 implementation
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2_response).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([new/1]).
-export([new/2]).
-export([new/4]).
-export([new/6]).
-export([new/7]).
-export([access_token/1]).
-export([access_token/2]).
-export([access_code/1]).
-export([access_code/2]).
-export([refresh_token/1]).
-export([refresh_token/2]).
-export([refresh_token_expires_in/1]).
-export([refresh_token_expires_in/2]).
-export([resource_owner/1]).
-export([resource_owner/2]).
-export([expires_in/1]).
-export([expires_in/2]).
-export([scope/1]).
-export([scope/2]).
-export([token_type/1]).
-export([to_proplist/1]).
-ifndef(pre17).
-export([to_map/1]).
-endif.

-export_type([response/0]).

%%%_* Macros ===========================================================
-define(TOKEN_TYPE, <<"bearer">>).

%%%_ * Types -----------------------------------------------------------
-record(response, {
          access_token              :: oauth2:token()
          ,access_code              :: oauth2:token()
          ,expires_in               :: oauth2:lifetime()
          ,resource_owner           :: term()
          ,scope                    :: oauth2:scope()
          ,refresh_token            :: oauth2:token()
          ,refresh_token_expires_in :: oauth2:lifetime()
          ,token_type = ?TOKEN_TYPE :: binary()
         }).

-type response() :: #response{}.
-type token()    :: oauth2:token().
-type lifetime() :: oauth2:lifetime().
-type scope()    :: oauth2:scope().

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
-spec new(token()) -> response().
new(AccessToken) ->
    #response{access_token = AccessToken}.

-spec new(token(), lifetime()) -> response().
new(AccessToken, ExpiresIn) ->
    #response{access_token = AccessToken, expires_in = ExpiresIn}.

-spec new(token(), lifetime(), term(), scope()) -> response().
new(AccessToken, ExpiresIn, ResOwner, Scope) ->
    #response{ access_token   = AccessToken
             , expires_in     = ExpiresIn
             , resource_owner = ResOwner
             , scope          = Scope
             }.

-spec new(token(), lifetime(), term(), scope(), token(), lifetime()) -> response().
new(AccessToken, ExpiresIn, ResOwner, Scope, RefreshToken, RExpiresIn) ->
    #response{ access_token             = AccessToken
             , expires_in               = ExpiresIn
             , resource_owner           = ResOwner
             , scope                    = Scope
             , refresh_token            = RefreshToken
             , refresh_token_expires_in = RExpiresIn
             }.

-spec new(_, lifetime(), term(), scope(), _, _, token()) -> response().
new(_, ExpiresIn, ResOwner, Scope, _, _, AccessCode) ->
    #response{ access_code    = AccessCode
             , expires_in     = ExpiresIn
             , resource_owner = ResOwner
             , scope          = Scope
             }.

-spec access_token(response()) -> {ok, token()} | {error, not_set}.
access_token(#response{access_token = undefined})   -> {error, not_set};
access_token(#response{access_token = AccessToken}) -> {ok, AccessToken}.

-spec access_token(response(), token()) -> response().
access_token(Response, NewAccessToken) ->
    Response#response{access_token = NewAccessToken}.

-spec access_code(response())  -> {ok, token()} | {error, not_set}.
access_code(#response{access_code = undefined})  -> {error, not_set};
access_code(#response{access_code = AccessCode}) -> {ok, AccessCode}.

-spec access_code(response(), token()) -> response().
access_code(Response, NewAccessCode) ->
    Response#response{access_code = NewAccessCode}.

-spec expires_in(response()) -> {ok, lifetime()} | {error, not_set}.
expires_in(#response{expires_in = undefined}) -> {error, not_set};
expires_in(#response{expires_in = ExpiresIn}) -> {ok, ExpiresIn}.

-spec expires_in(response(), lifetime()) -> response().
expires_in(Response, NewExpiresIn) ->
    Response#response{expires_in = NewExpiresIn}.

-spec scope(response()) -> {ok, scope()} | {error, not_set}.
scope(#response{scope = undefined}) -> {error, not_set};
scope(#response{scope = Scope})     -> {ok, Scope}.

-spec scope(response(), scope()) -> response().
scope(Response, NewScope) -> Response#response{scope = NewScope}.

-spec refresh_token(response()) -> {ok, token()} | {error, not_set}.
refresh_token(#response{refresh_token = undefined})    -> {error, not_set};
refresh_token(#response{refresh_token = RefreshToken}) -> {ok, RefreshToken}.

-spec refresh_token(response(), token()) -> response().
refresh_token(Response, NewRefreshToken) ->
    Response#response{refresh_token = NewRefreshToken}.

-spec refresh_token_expires_in(response()) -> {ok, lifetime()} | {error, not_set}.
refresh_token_expires_in(#response{refresh_token = undefined})    ->
    {error, not_set};
refresh_token_expires_in(#response{refresh_token_expires_in = RefreshTokenExpiresIn}) ->
    {ok, RefreshTokenExpiresIn}.

-spec refresh_token_expires_in(response(), lifetime()) -> response().
refresh_token_expires_in(Response, NewRefreshTokenExpiresIn) ->
    Response#response{refresh_token_expires_in = NewRefreshTokenExpiresIn}.

-spec resource_owner(response()) -> {ok, term()}.
resource_owner(#response{resource_owner = ResOwner}) ->
    {ok, ResOwner}.

-spec resource_owner(response(), term()) -> response().
resource_owner(Response, NewResOwner) ->
    Response#response{resource_owner = NewResOwner}.

-spec token_type(response()) -> {ok, binary()}.
token_type(#response{}) ->
    {ok, ?TOKEN_TYPE}.

-spec to_proplist(response()) -> proplists:proplist().
to_proplist(Response) ->
    response_foldr(Response, fun(Key, Value, Acc) -> [{Key, Value} | Acc] end, []).

-ifndef(pre17).
-ifdef(pre18).
-spec to_map(response()) -> map(binary(), any()).
-else.
-spec to_map(response()) -> #{binary() => any()}.
-endif.
to_map(Response) ->
    response_foldr(Response, fun(Key, Value, Acc) -> maps:put(Key, Value, Acc) end, maps:new()).
-endif.

%%%_* Private functions ================================================
-spec response_foldr(Response, Fun, Acc0) -> Return when
    Response :: response(),
    Fun      :: fun((Key::binary(), Value::any(), Acc::any()) -> Acc::any()),
    Acc0     :: any(),
    Return   :: any().
response_foldr(Record, Fun, Acc0) ->
    Keys = record_info(fields, response),
    Values = tl(tuple_to_list(Record)), %% Head is 'response'!
    response_foldr(Keys, Values, Fun, Acc0).

response_foldr([], [], _Fun, Acc0) ->
    Acc0;
response_foldr([_ | Ks], [undefined | Vs], Fun, Acc) ->
    response_foldr(Ks, Vs, Fun, Acc);
response_foldr([refresh_token_expires_in | Ks], [V | Vs], Fun, Acc) ->
    Fun(<<"refresh_token_expires_in">>, V, response_foldr(Ks, Vs, Fun, Acc));
response_foldr([expires_in | Ks], [V | Vs], Fun, Acc) ->
    Fun(<<"expires_in">>, V, response_foldr(Ks, Vs, Fun, Acc));
response_foldr([K | Ks], [V | Vs], Fun, Acc) ->
    Key = atom_to_binary(K, latin1),
    Value = to_binary(V),
    Fun(Key, Value, response_foldr(Ks, Vs, Fun, Acc)).

to_binary(Binary) when is_binary(Binary) ->
    Binary;
to_binary([Binary]) when is_binary(Binary) ->
    Binary;
to_binary([BinaryHead | Tail]) when is_binary(BinaryHead) ->
    <<BinaryHead/binary, " ", (to_binary(Tail))/binary>>;
to_binary(List) when is_list(List) ->
    to_binary(list_to_binary(List));
to_binary(Atom) when is_atom(Atom) ->
    to_binary(atom_to_list(Atom));
to_binary(Float) when is_float(Float) ->
    to_binary(float_to_list(Float));
to_binary(Integer) when is_integer(Integer) ->
    to_binary(integer_to_list(Integer));
to_binary({Key, Value}) ->
    {to_binary(Key), to_binary(Value)};
to_binary(Term) ->
    to_binary(term_to_binary(Term)).

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
