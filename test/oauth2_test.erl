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
                        ClientId = "123abcABC",

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
                        ?assertEqual(T, 30),
                        ?assertNotEqual(T, 40),
                        B = oauth2:verify_token(access_token, oauth2_mock_db,
                                                Au, ClientId),
                        ?assertMatch({ok, _}, B),
                        %%
                        %% Check expired token
                        Value = {oauth2,"123abcABC",1330632816,"This That"},
                        Token = "123",
                        oauth2_mock_db:set(access, ClientId++"#"++Token, Value),
                        C = oauth2:verify_token(access_token, oauth2_mock_db,
                                                Token, ClientId),
                        ?assertEqual(C, {error, invalid_token}),
                        %%
                        %% Check invalid token
                        ClientId2 = "234qwerty",
                        D = oauth2:authorize(code, oauth2_mock_db, ClientId2,
                                             RedirectUri, Scope, State),
                        {ok, Au2, _, _} = D,
                        ?assertEqual({error, invalid_token},
                                     oauth2:verify_token(access_token,
                                                         oauth2_mock_db,
                                                         Au2, ClientId2)),

                        oauth2_mock_db:delete_table()
                end 
            }
        ]
    }.

