-module(oauth2_test).

-include_lib("eunit/include/eunit.hrl").

oauth2_test_() ->
    {foreach,
        fun() ->
                ok
        end,
        fun(_) ->
                ok
        end,
        [
            {"web server (authentication code flow)",
                fun() ->
                        ok
                end
            },
            {"client side (implicit flow) ",
                fun() ->
                        oauth2_mock_db:init(),

                        RedirectUri = "http://REDIRECT.URL/here?this=that",
                        Scope = "This That",
                        State = "",
                        %State2 = "Just a little state",
                        AccessType = offline,
                        ClientId = "123abcABC",

                        %% Standard "online" authorization
                        A = oauth2:authorize(token, oauth2_mock_db, ClientId,
                                             RedirectUri, Scope, State),
                        ?assertMatch({ok, _, _, _}, A),
                        {_, Au, Ru, T} = A,
                        {S, N, P, Q, F} = mochiweb_util:urlsplit(Ru),
                        {S2, N2, P2, Q2, _} = mochiweb_util:urlsplit(RedirectUri),
                        F2 = mochiweb_util:parse_qs(F),
                        ?assertEqual(S, S2),
                        ?assertEqual(N, N2),
                        ?assertEqual(P, P2),
                        ?assertEqual(Q, Q2),
                        ?assertEqual(Au, proplists:get_value("code", F2)),
                        ?assert(check_expire(T, 30)),
                        ?assertNot(check_expire(T, 40)),
                        
                        %% "offline" authorization
                        oauth2:authorize(token, oauth2_mock_db, ClientId,
                                             RedirectUri, Scope, State, AccessType),
                        oauth2_mock_db:delete_table(),
                        ok
                end 
            }
        ]
    }.

check_expire(Base, Diff) ->
    {Mega, Secs, _Micro} = now(),
    Diff2 = Mega * 1000000 + Secs + Diff,
    Diff2 =:= Base.

