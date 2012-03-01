-module(oauth2_mock_db).

-export([get/2, set/3, delete/2]).
-export([verify_redirect_uri/2]).

%% 
%% Non behavioral functions
-export([init/0, delete_table/0]).

-define(TAB_AUTH, auth).
-define(TAB_ACC, acc).

-behavior(oauth2_db).

get(auth, Key) ->
    get_tab(?TAB_AUTH, Key);
get(access, Key) ->
    get_tab(?TAB_ACC, Key).

set(auth, Key, Value) ->
    set_tab(?TAB_AUTH, Key, Value);
set(access, Key, Value) ->
    set_tab(?TAB_ACC, Key, Value).

delete(auth, Key) ->
    delete_tab(?TAB_AUTH, Key);
delete(access, Key) ->
    delete_tab(?TAB_ACC, Key).

verify_redirect_uri(_, _) ->
    true.

%%
%% Non behavioral functions
delete_tab(Table, Key) ->
    ets:delete(Table, Key).

set_tab(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}).

get_tab(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            undefined;
        [{_Key, Value}] ->
            {ok, Value}
    end.

init() ->
    ?TAB_AUTH = ets:new(?TAB_AUTH, [named_table, {read_concurrency, true}]),
    ?TAB_ACC = ets:new(?TAB_ACC, [named_table, {read_concurrency, true}]),
    ok.

delete_table() ->
    ets:delete(?TAB_AUTH),
    ets:delete(?TAB_ACC).

