-module(oauth2).

-export([is_authenticated/1, verify_token/2, is_perm_granted/2, get_auth_code/1]).

-include_lib("oauth2/include/oauth2.hrl").

is_authenticated(Req) when is_list(Req) ->
    Request = proplist_to_rec(Req, #oauth2{}),
    validate_client_id(Request#oauth2.client_id),
    validate_redirect_uri(Request#oauth2.redirect_uri),
    %{error, authorize_invalid_header};
    case Request#oauth2.error of
        undefined -> ok;
        "access_denied" -> {error, access_denied};
        _ -> {error, authorize_invalid_header}
    end;
is_authenticated(_) ->
    {error, bad_arg}.

is_perm_granted(_, _) ->
    true.

get_auth_code(_ClientId) ->
    AuthCode = generate_auth_code(),
    %%Save Auth Code for ClientId
    AuthCode.

verify_token(access_token, Token) ->
    %% TODO check token
    case Token of
        "hej" ->
            {ok, [{audience, "Client ID"}, {scope, "Which scope"},
                  {expires_in, "secs"}]};
        _ ->
            {error, invalid_token}
    end.

%% Internal API
%%

generate_auth_code() ->
    Chars = list_to_tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-&/"),
    rnd_auth(30, Chars).

rnd_auth(0, _) ->
    [];
rnd_auth(Len, C) ->
    [rnd_auth(C)|rnd_auth(Len-1, C)].
rnd_auth(C) ->
    element(random:uniform(tuple_size(C)), C).

validate_client_id(undefined) ->
    {error, wrong_client_id};
validate_client_id(_ClientId) ->
    true.

validate_redirect_uri(undefined) ->
    {error, wrong_redirect_uri};
validate_redirect_uri(_RedirectUri) ->
    true.

proplist_to_rec([], Acc) ->
    Acc;
proplist_to_rec([{HH, HT}|T], Acc) ->
    proplist_to_rec(T, set_rec(list_to_existing_atom(HH), HT, Acc)).

set_rec(response_type, Value, Rec) ->
    Rec#oauth2{response_type=Value};
set_rec(client_id, Value, Rec) ->
    Rec#oauth2{client_id=Value};
set_rec(redirect_uri, Value, Rec) ->
    Rec#oauth2{redirect_uri=Value};
set_rec(scope, Value, Rec) ->
    Rec#oauth2{scope=Value};
set_rec(state, Value, Rec) ->
    Rec#oauth2{state=Value};
set_rec(access_type, Value, Rec) ->
    Rec#oauth2{access_type=Value};
set_rec(approval_prompt, Value, Rec) ->
    Rec#oauth2{approval_prompt=Value};
set_rec(code, Value, Rec) ->
    Rec#oauth2{code=Value};
set_rec(client_secret, Value, Rec) ->
    Rec#oauth2{client_secret=Value};
set_rec(grant_type, Value, Rec) ->
    Rec#oauth2{grant_type=Value};
set_rec(access_token, Value, Rec) ->
    Rec#oauth2{access_token=Value};
set_rec(refresh_token, Value, Rec) ->
    Rec#oauth2{refresh_token=Value};
set_rec(expires_in, Value, Rec) ->
    Rec#oauth2{expires_in=Value};
set_rec(error, Value, Rec) ->
    Rec#oauth2{error=Value};
set_rec(token_type, Value, Rec) ->
    Rec#oauth2{token_type=Value}.

