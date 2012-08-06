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

-module(oauth2_example_auth).

-export([
         init/3
         ,rest_init/2
         ,allowed_methods/2
        ]).

-export([
         content_types_provided/2
         ,content_types_accepted/2
        ]).

-export([
         process_post/2
         ,process_get/2
        ]).

%%%===================================================================
%%% Cowboy callbacks
%%%===================================================================

init(_Transport, _Req, _Opts) ->
    %% Compile the DTL template used for the authentication
    %% form in the implicit grant flow.
    ok = erlydtl:compile(filename:join(["priv", "static", "auth_form.dtl"]),
                         auth_form),
    {upgrade, protocol, cowboy_http_rest}.

rest_init(Req, _Opts) ->
    {ok, Req, undefined_state}.

content_types_provided(Req, State) ->
    {[{{<<"text">>, <<"html">>, []}, process_get}], Req, State}.

content_types_accepted(Req, State) ->
    {[{{<<"application">>, <<"json">>, []}, process_post},
      {{<<"application">>, <<"x-www-form-urlencoded">>, []}, process_post}],
     Req, State}.

allowed_methods(Req, State) ->
    {['POST', 'GET'], Req, State}.

process_post(Req, State) ->
    {ok, Body, Req2} = cowboy_http_req:body(Req),
    Params = decode_form(Body),
    {ok, Reply} =
        case lists:max([proplists:get_value(K, Params)
                        || K <- [<<"grant_type">>, <<"response_type">>]]) of
            <<"password">> ->
                process_password_grant(Req2, Params);
            <<"client_credentials">> ->
                process_client_credentials_grant(Req2, Params);
            <<"token">> ->
                process_implicit_grant_stage2(Req2, Params);
            _ ->
                cowboy_http_req:reply(400, [], <<"Bad Request.">>, Req2)
        end,
    {halt, Reply, State}.    

process_get(Req, State) ->
    {ResponseType, Req2} = cowboy_http_req:qs_val(<<"response_type">>, Req),
    {ok, Reply} = 
        case ResponseType of
            <<"token">> ->
                {Req3, Params} =
                    lists:foldl(fun(Name, {R, Acc}) ->
                                        {Val, R2} =
                                            cowboy_http_req:qs_val(Name, R),
                                        {R2, [{Name, Val}|Acc]}
                                end,
                                {Req2, []},
                                [<<"client_id">>,
                                 <<"redirect_uri">>,
                                 <<"scope">>,
                                 <<"state">>]),
                process_implicit_grant(Req3, Params);
            _ ->
                JSON = jsx:encode([{error, <<"unsupported_respose_type">>}]),
                cowboy_http_req:reply(400, [], JSON, Req2)
        end,
    {halt, Reply, State}.

%%%===================================================================
%%% Grant type handlers
%%%===================================================================

process_password_grant(Req, Params) ->
    Username = proplists:get_value(<<"username">>, Params),
    Password = proplists:get_value(<<"password">>, Params),
    Scope    = proplists:get_value(<<"scope">>, Params, <<"">>),
    emit_response(oauth2:authorize_password(Username, Password, Scope), Req).

process_client_credentials_grant(Req, Params) ->
    {<<"Basic ", Credentials/binary>>, Req2} =
        cowboy_http_req:header('Authorization', Req),
    [Id, Secret] = binary:split(base64:decode(Credentials), <<":">>),
    Scope = proplists:get_value(<<"scope">>, Params),
    emit_response(oauth2:authorize_client_credentials(Id, Secret, Scope), Req2).

process_implicit_grant(Req, Params) ->
    State       = proplists:get_value(<<"state">>, Params),
    Scope       = proplists:get_value(<<"scope">>, Params, <<>>),
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    case oauth2:verify_redirection_uri(ClientId, RedirectUri) of
        ok ->
            %% Pass the scope, state and redirect URI to the browser
            %% as hidden form parameters, allowing them to "propagate"
            %% to the next stage.
            {ok, Html} = auth_form:render([{redirect_uri, RedirectUri},
                                           {client_id, ClientId},
                                           {state, State},
                                           {scope, Scope}]),
            cowboy_http_req:reply(200, [], Html, Req);
        %% TODO: Return an OAuth2 response code here.
        %% The returned Reason might not be valid in an OAuth2 context.
        {error, Reason} ->
            redirect_resp(RedirectUri,
                           [{<<"error">>, to_binary(Reason)},
                            {<<"state">>, State}],
                           Req)
    end.

process_implicit_grant_stage2(Req, Params) ->
    ClientId    = proplists:get_value(<<"client_id">>, Params),
    RedirectUri = proplists:get_value(<<"redirect_uri">>, Params),
    Username    = proplists:get_value(<<"username">>, Params),
    Password    = proplists:get_value(<<"password">>, Params),
    State       = proplists:get_value(<<"state">>, Params),
    Scope       = proplists:get_value(<<"scope">>, Params),
    case oauth2:verify_redirection_uri(ClientId, RedirectUri) of
        ok ->
            case oauth2:authorize_password(Username, Password, Scope) of
                {ok, Response} ->
                    Props = [{<<"state">>, State}
                             | oauth2_response:to_proplist(Response)],
                    redirect_resp(RedirectUri, Props, Req);
                {error, Reason} ->
                    redirect_resp(RedirectUri,
                                  [{<<"error">>, to_binary(Reason)},
                                   {<<"state">>, State}],
                                  Req)
            end;
        {error, _} ->
            %% This should not happen. Redirection URI was
            %% supposedly verified in the previous step, so
            %% someone must have been tampering with the
            %% hidden form values.
            cowboy_http_req:reply(400, Req)
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

emit_response(AuthResult, Req) ->
    {Code, JSON} =
        case AuthResult of
            {ok, Response} ->
                {200, jsx:encode(oauth2_response:to_proplist(Response))};
            {error, Reason} ->
                {400, jsx:encode([{error, to_binary(Reason)}])}
        end,
    cowboy_http_req:reply(Code, [], JSON, Req).

decode_form(Form) ->
    RawForm = cowboy_http:urldecode(Form),
    Pairs = binary:split(RawForm, <<"&">>, [global]),
    lists:map(fun(Pair) ->
                      [K, V] = binary:split(Pair, <<"=">>),
                      {K, V}
              end,
              Pairs).

to_binary(Atom) when is_atom(Atom) ->
    list_to_binary(atom_to_list(Atom)).

redirect_resp(RedirectUri, FragParams, Req) ->
    Frag = binary_join([<<(cowboy_http:urlencode(K))/binary, "=",
                          (cowboy_http:urlencode(V))/binary>>
                            || {K, V} <- FragParams],
                       <<"&">>),
    Header = [{'Location', <<RedirectUri/binary, "#", Frag/binary>>}],
    cowboy_http_req:reply(302, Header, <<>>, Req).

binary_join([H], _Sep) ->
    <<H/binary>>;
binary_join([H|T], Sep) ->
    <<H/binary, Sep/binary, (binary_join(T, Sep))/binary>>;
binary_join([], _Sep) ->
    <<>>.
