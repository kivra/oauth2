-module(oauth2_db).

-export([behaviour_info/1]).

behaviour_info(callbacks) ->
    [{get, 1},
     {set, 2},
     {delete, 1}];
behaviour_info(_) ->
    undefined.


