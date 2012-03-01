-module(oauth2_mock_db).

-export([get/1, set/2, delete/1]).
-export([init/0, delete_table/0]).

-behavior(oauth2_db).

get(Key) ->
    case ets:lookup(?MODULE, Key) of
        [] ->
            undefined;
        [{_Key, Value}] ->
            {ok, Value}
    end.

set(Key, Value) ->
    ets:insert(?MODULE, {Key, Value}).

delete(Key) ->
    ets:delete(?MODULE, Key).

%%
%% Non behavioral functions
init() ->
    ?MODULE = ets:new(?MODULE, [named_table, {read_concurrency, true}]),
    ok.

delete_table() ->
    ets:delete(?MODULE).

