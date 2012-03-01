-module(oauth2).

-export([authorize/6]).
-export([verify_token/4]).

-define(DEF_AUTH_TOKEN_EXPIRE, 30).

-record(oauth2, {client_id :: string(),
                 expires :: non_neg_integer(),
                 scope :: list(string())
                }).

authorize(ResponseType, Db, ClientId, RedirectUri, Scope, State) ->
    case Db:verify_redirect_uri(ClientId, RedirectUri) of
        false ->
            {error, redirect_uri_mismatch};
        true ->
            AuthCode = generate_auth_code(),
            Data = #oauth2{client_id=ClientId,
                           expires=seconds_since_epoch(?DEF_AUTH_TOKEN_EXPIRE),
                           scope=Scope},
            Key = generate_key(ClientId, AuthCode),
            case ResponseType of
                token -> Db:set(access, Key, Data);
                code -> Db:set(auth, Key, Data)
            end,
            NewRedirectUri = get_redirect_uri(ResponseType, AuthCode, RedirectUri, State),
            {ok, AuthCode, NewRedirectUri, calculate_expires_in(Data#oauth2.expires)}
    end.

verify_token(access_token, Db, Token, ClientId) ->
    case Db:get(access, generate_key(ClientId, Token)) of
        {ok, Data} ->
            ClientId = Data#oauth2.client_id,
            Expires = Data#oauth2.expires,
            Scope = Data#oauth2.scope,

            case calculate_expires_in(Expires) > 0 of
                false ->
                    Db:delete(access,  generate_key(ClientId, Token)),
                    {error, invalid_token};
                true ->
                    {ok, [{audience, ClientId}, {scope, Scope},
                          {expires_in, calculate_expires_in(Expires)}]}
            end;
        _ ->
            {error, invalid_token}
    end.

%% Internal API
%%
get_redirect_uri(Type, Code, Uri, State) ->
    {S, N, P, Q, _} = mochiweb_util:urlsplit(Uri),
    State2 = case State of
        undefined -> [];
        "" -> [];
        StateVal -> [{state, StateVal}]
    end,
    Q2 = mochiweb_util:parse_qs(Q),
    CF = [{code, Code}],
    case Type of
        token ->
            Q3 = lists:append([State2, Q2]),
            CF2 = mochiweb_util:urlencode(CF),
            Query = mochiweb_util:urlencode(Q3),
            mochiweb_util:urlunsplit({S, N, P, Query, CF2});
        code ->
            Q3 = lists:append([CF, State2, Q2]),
            Query = mochiweb_util:urlencode(Q3),
            mochiweb_util:urlunsplit({S, N, P, Query, ""})
    end.

generate_key(ClientId, AuthCode) ->
    lists:flatten([ClientId, "#", AuthCode]).

generate_auth_code() ->
    Chars = list_to_tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"),
    random:seed(now()),
    rnd_auth(30, Chars).

rnd_auth(0, _) ->
    [];
rnd_auth(Len, C) ->
    [rnd_auth(C)|rnd_auth(Len-1, C)].
rnd_auth(C) ->
    element(random:uniform(tuple_size(C)), C).

calculate_expires_in(Expire) ->
    Expire - seconds_since_epoch(0).

seconds_since_epoch(Diff) ->
    {Mega, Secs, _Micro} = now(),
    Mega * 1000000 + Secs + Diff.

