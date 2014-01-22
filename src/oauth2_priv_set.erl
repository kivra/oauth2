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
-module(oauth2_priv_set).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([new/1]).
-export([union/2]).
-export([is_subset/2]).
-export([is_member/2]).

-export_type([priv_set/0]).

%%%_ * Types -----------------------------------------------------------
%% Invariant: Children are sorted increasingly by name.
-type priv_tree() :: {node, Name :: binary(), Children :: [priv_tree()]} | '*'.
%% Invariant:
%% The list of trees is sorted increasingly by the name of the root node.
-type priv_set()  :: [priv_tree()].

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
%% @doc Constructs a new priv_set from a single path or a list of paths.
%%      A path denotes a single privilege.
-spec new(binary() | [binary()]) -> priv_set().
new(Paths) when is_list(Paths) ->
    lists:foldl(fun union/2, [], [make_forest(Path) || Path <- Paths]);
new(Path) when is_binary(Path) ->
    make_forest(Path).

%% @doc Returns the union of Set1 and Set2, i.e., a set such that
%%      any path present in either Set1 or Set2 is also present in the result.
-spec union(priv_set(), priv_set()) -> priv_set().
union([H1={node, Name1, _}|T1], [H2={node, Name2, _}|T2]) when Name1 < Name2 ->
    [H1|union(T1, [H2|T2])];
union([H1={node, Name1, _}|T1], [H2={node, Name2, _}|T2]) when Name1 > Name2 ->
    [H2|union([H1|T1], T2)];
union([{node, Name, S1}|T1], [{node, Name, S2}|T2]) ->
    [{node, Name, union(S1, S2)}|union(T1, T2)];
union(['*'|_], _) -> ['*']; %% '*' in union with anything is still '*'.
union(_, ['*'|_]) -> ['*'];
union([], Set)    -> Set;
union(Set, [])    -> Set.

%% @doc Return true if Set1 is a subset of Set2, i.e., if
%%      every privilege held by Set1 is also held by Set2.
-spec is_subset(priv_set(), priv_set()) -> boolean().
is_subset([{node, N1, _}|_], [{node, N2, _}|_]) when N1 < N2 ->
    false; %% This tree isn't present in Set2 as per the invariant.
is_subset(Set1 = [{node, N1, _}|_], [{node, N2, _}|T2]) when N1 > N2 ->
    is_subset(Set1, T2);
is_subset([{node, Name, S1}|T1], [{node, Name, S2}|T2]) ->
    case is_subset(S1, S2) of
        true  -> is_subset(T1, T2);
        false -> false
    end;
is_subset(['*'|_], ['*'|_]) -> true; %% '*' is only a subset of '*'.
is_subset(_, ['*'|_])       -> true; %% Everything is a subset of '*'.
is_subset([], _)            -> true; %% The empty set is a subset of every set.
is_subset(_, _)             -> false.

%% @doc Returns true if Path is present in Set, i.e, if
%%      the privilege denoted by Path is contained within Set.
-spec is_member(binary(), priv_set()) -> boolean().
is_member(Path, Set) -> is_subset(make_forest(Path), Set).


%%%_* Private functions ================================================
-spec make_forest(binary() | list()) -> priv_set().
make_forest(Path) when is_binary(Path) ->
    make_forest(binary:split(Path, <<".">>, [global]));
make_forest(Path) when is_list(Path) ->
    [make_tree(Path)].

-spec make_tree([binary()]) -> priv_tree().
make_tree([<<"*">>|_]) -> '*';
make_tree([N])         -> make_node(N, []);
make_tree([H|T])       -> make_node(H, [make_tree(T)]).

-spec make_node(binary(), [priv_tree()]) -> priv_tree().
make_node(Name, Children) -> {node, Name, Children}.

%%%_* Tests ============================================================
-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%%%_* Emacs ============================================================
%%% Local Variables:
%%% allout-layout: t
%%% erlang-indent-level: 4
%%% End:
