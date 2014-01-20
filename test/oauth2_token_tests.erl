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

-module(oauth2_token_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test cases
%%%===================================================================

proper_type_spec_test_() ->
    {timeout, 1200, [{?LINE,
                      fun() -> proper:check_specs(oauth2_token,
                                                  [{to_file, user}]) end}]}.

generate_test() ->
    Token = oauth2_token:generate([]),
    ?assertEqual(byte_size(Token), 32),
    ?assert(lists:all(fun is_alphanum/1, binary_to_list(Token))).

generate_low_entropy_test_() ->
    {setup,
     fun() ->
             meck:new(oauth2_token, [passthrough]),
             meck:expect(oauth2_token, strong_rand_bytes_proxy,
                         fun(_) -> throw(low_entropy) end)
     end,
     fun(_) ->
             meck:unload(oauth2_token)
     end,
     fun(_) ->
             [
              ?_assertEqual(byte_size(oauth2_token:generate([])), 32),
              ?_assert(
                 lists:all(fun is_alphanum/1,
                           binary_to_list(oauth2_token:generate([]))))
             ]
     end}.

%%%===================================================================
%%% Utility functions
%%%===================================================================

%% @doc Returns true for alphanumeric ASCII characters, false for all others.
-spec is_alphanum(Char :: char()) -> boolean().
is_alphanum(C) when C >= 16#30 andalso C =< 16#39 -> true;
is_alphanum(C) when C >= 16#41 andalso C =< 16#5A -> true;
is_alphanum(C) when C >= 16#61 andalso C =< 16#7A -> true;
is_alphanum(_)                                    -> false.
