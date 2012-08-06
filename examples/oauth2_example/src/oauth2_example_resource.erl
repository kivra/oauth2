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

-module(oauth2_example_resource).

-export([
         init/3
         ,rest_init/2
         ,allowed_methods/2
         ,is_authorized/2
        ]).

-export([
         content_types_provided/2
         ,content_types_accepted/2
        ]).

-export([
         process_get/2
         ,process_put/2
        ]).

%%%===================================================================
%%% Cowboy callbacks
%%%===================================================================

init(_Transport, _Req, _Opts) ->
    {upgrade, protocol, cowboy_http_rest}.

rest_init(Req, _Opts) ->
    {ok, Req, undefined_state}.

allowed_methods(Req, State) ->
    {['GET', 'PUT'], Req, State}.

is_authorized(Req, State) ->
    case get_access_token(Req) of
        {ok, Token} ->
            case oauth2:verify_access_token(Token) of
                {ok, _Identity} ->
                    {true, Req, State};
                {error, access_denied} ->
                    {{false, <<"Bearer">>}, Req, State}
            end;
        {error, _} ->
            {{false, <<"Bearer">>}, Req, State}
    end.

content_types_provided(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_get}], Req, State}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_put}], Req, State}.

process_put(Req, State) ->
    {ok, cowboy_http_req:reply(201, Req), State}.

process_get(Req, State) ->
    {ok, cowboy_http_req:reply(204, Req), State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get_access_token(Req) ->
    case cowboy_http_req:header('Authorization', Req) of
        {<<"Bearer ", Token/binary>>, _Req} ->
            {ok, Token};
        _ ->
            case cowboy_http_req:qs_val(<<"access_token">>, Req) of
                {Token, _Req} ->
                    {ok, Token};
                _ ->
                    {error, missing}
            end
    end.
