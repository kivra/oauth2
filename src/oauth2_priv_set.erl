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

-module(oauth2_priv_set).

%%% API
-export([new/1]).
-export([union/2]).
-export([is_subset/2]).
-export([is_member/2]).

%%%===================================================================
%%% API
%%%===================================================================

%% Invariant: Children are sorted increasingly by name.
-type priv_tree() :: {node, Name :: binary(), Children :: [priv_tree()]} | '*'.
%% Invariant:
%% The list of trees is sorted increasingly by the name of the root node.
-type priv_set()  :: [priv_tree()].

%% @doc Constructs a new priv_set from a single path or a list of paths.
%% A path denotes a single privilege.
%% @end
-spec new(Paths) -> PrivSet when
    Paths   :: binary() | [binary()],
    PrivSet :: priv_set().
new(Paths) when is_list(Paths) ->
    lists:foldl(fun union/2, [], [make_forest(Path) || Path <- Paths]);
new(Path) when is_binary(Path) ->
    make_forest(Path).

%% @doc Returns the union of Set1 and Set2, i.e., a set such that
%% any path present in either Set1 or Set2 is also present in the result.
%% @end
-spec union(Set1, Set2) -> Union when
    Set1  :: priv_set(),
    Set2  :: priv_set(),
    Union :: priv_set().
union([H1={node, Name1, _}|T1], [H2={node, Name2, _}|T2]) when Name1 < Name2 ->
    [H1|union(T1, [H2|T2])];
union([H1={node, Name1, _}|T1], [H2={node, Name2, _}|T2]) when Name1 > Name2 ->
    [H2|union([H1|T1], T2)];
union([{node, Name, S1}|T1], [{node, Name, S2}|T2]) ->
    [{node, Name, union(S1, S2)}|union(T1, T2)];
union(['*'|_], _) -> %% '*' in union with anything is still '*'.
    ['*'];
union(_, ['*'|_]) ->
    ['*'];
union([], Set) ->
    Set;
union(Set, []) ->
    Set.

%% @doc Return true if Set1 is a subset of Set2, i.e., if
%% every privilege held by Set1 is also held by Set2.
%% @end
-spec is_subset(Set1, Set2) -> Result when
    Set1   :: priv_set(),
    Set2   :: priv_set(),
    Result :: boolean().
is_subset([{node, Name1, _}|_], [{node, Name2, _}|_]) when Name1 < Name2 ->
    false; %% This tree isn't present in Set2 as per the invariant.
is_subset(Set1 = [{node, Name1, _}|_], [{node, Name2, _}|T2]) when Name1 > Name2 ->
    is_subset(Set1, T2);
is_subset([{node, Name, S1}|T1], [{node, Name, S2}|T2]) ->
    case is_subset(S1, S2) of
        true ->
            is_subset(T1, T2);
        false ->
            false
    end;
is_subset(['*'|_], ['*'|_]) -> %% '*' is only a subset of '*'.
    true;
is_subset(_, ['*'|_]) -> %% Everything is a subset of '*'.
    true;
is_subset([], _) -> %% The empty set is a subset of every set.
    true;
is_subset(_, _) ->
    false.

%% @doc Returns true if Path is present in Set, i.e, if
%% the privilege denoted by Path is contained within Set.
%% @end
-spec is_member(Path, Set) -> Result when
    Path   :: binary(),
    Set    :: priv_set(),
    Result ::  boolean().
is_member(Path, Set) ->
    is_subset(make_forest(Path), Set).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec make_forest(Path) -> Forest when
    Path   :: binary() | list(),
    Forest :: priv_set().
make_forest(Path) when is_binary(Path) ->
    make_forest(binary:split(Path, <<".">>, [global]));
make_forest(Path) when is_list(Path) ->
    [make_tree(Path)].

-spec make_tree(Path) -> Tree when
    Path :: [binary()],
    Tree :: priv_tree().
make_tree([<<"*">>|_]) ->
    '*';
make_tree([N]) ->
    make_node(N, []);
make_tree([H|T]) ->
    make_node(H, [make_tree(T)]).

-spec make_node(Name, Children) -> Node when
    Name     :: binary(),
    Children :: [priv_tree()],
    Node     :: priv_tree().
make_node(Name, Children) ->
    {node, Name, Children}.
