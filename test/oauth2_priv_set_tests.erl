%% ----------------------------------------------------------------------------
%%
%% oauth2: Erlang OAuth 2.0 implementation
%%
%% Copyright (c) 2012-2014 Kivra
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

-module(oauth2_priv_set_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test cases
%%%===================================================================

proper_type_spec_test_() ->
    {timeout, 1200, [{?LINE,
                      fun() -> proper:check_specs(oauth2_priv_set,
                                                  [{to_file, user}]) end}]}.

new_test_() ->
    [
     ?_assert(oauth2_priv_set:is_member(
                <<"x.y.z">>,
                oauth2_priv_set:new(<<"x.y.z">>))),
     ?_assert(oauth2_priv_set:is_member(
                <<"a.b.c">>,
                oauth2_priv_set:new([<<"a.b.c">>, <<"a.b.d">>]))),
     ?_assertNot(oauth2_priv_set:is_member(
                   <<"a.b.c">>,
                   oauth2_priv_set:new(<<"x.y.z">>))),
     ?_assertNot(oauth2_priv_set:is_member(
                   <<"a.b.e">>,
                   oauth2_priv_set:new([<<"a.b.c">>, <<"a.b.a">>])))
    ].

is_subset_test_() ->
    [
     ?_assert(oauth2_priv_set:is_subset(
                oauth2_priv_set:new(<<"a.b.c.d.e">>),
                oauth2_priv_set:new([
                                     <<"a.b">>,
                                     <<"a.b.x.y">>,
                                     <<"a.b.z.x">>,
                                     <<"a.b.k.d.g.e">>,
                                     <<"a.b.m.n.p.q">>,
                                     <<"a.b.c.d.*">>
                                    ]))),
     ?_assert(oauth2_priv_set:is_subset(
                oauth2_priv_set:new(<<"a.b.c">>),
                oauth2_priv_set:new([<<"a.b.c">>, <<"a.s.d.f.g.h">>]))),
     ?_assert(oauth2_priv_set:is_subset(
                oauth2_priv_set:new(<<"x.y.z">>),
                oauth2_priv_set:new([<<"x.y">>, <<"x.*">>]))),
     ?_assert(oauth2_priv_set:is_subset(
                oauth2_priv_set:new(<<"x.y.z">>),
                oauth2_priv_set:new([<<"x.*">>, <<"x.y">>]))),
     ?_assert(oauth2_priv_set:is_subset(
                oauth2_priv_set:new(<<"x.*">>),
                oauth2_priv_set:new([<<"a.*">>, <<"x.*">>]))),
     ?_assertNot(oauth2_priv_set:is_subset(
                   oauth2_priv_set:new(<<"a.b.c">>),
                   oauth2_priv_set:new(<<"a.b">>))),
     ?_assertNot(oauth2_priv_set:is_subset(
                   oauth2_priv_set:new(<<"x.y.z">>),
                   oauth2_priv_set:new(<<"x.z.*">>))),
     ?_assertNot(oauth2_priv_set:is_subset(
                   oauth2_priv_set:new(<<"a.*">>),
                   oauth2_priv_set:new([<<"a.b.*">>,
                                        <<"a.c.*">>,
                                        <<"a.d.*">>,
                                        <<"a.e.*">>,
                                        <<"a.f.z">>])))
    ].
