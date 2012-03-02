-module(oauth2_test).

-include_lib("eunit/include/eunit.hrl").

oauth2_test_() ->
    {foreach, local,
        fun() ->
                oauth2_mock_db:init()
        end,
        fun(_) ->
                oauth2_mock_db:delete_table()
        end,
        [
            {"web server (authentication code flow)",
                fun() ->
                        RedirectUri = "http://REDIRECT.URL/here?this=that",
                        Scope = "This That",
                        State = [],
                        ClientId = "123abcABC",

                        A = oauth2:authorize(code, oauth2_mock_db, ClientId,
                                             RedirectUri, Scope, State),
                        ?assertMatch({ok, _, _, _}, A),
                        {_, Au, Ru, T} = A,
                        {S, N, P, Q, _F} = mochiweb_util:urlsplit(Ru),
                        {S2, N2, P2, _Q2, _} = mochiweb_util:urlsplit(RedirectUri),
                        Q2 = mochiweb_util:parse_qs(Q),
                        ?assertEqual(S, S2),
                        ?assertEqual(N, N2),
                        ?assertEqual(P, P2),
                        ?assertEqual(Au, proplists:get_value("code", Q2)),
                        ?assertEqual(30, T),

                        %%
                        %% Check valid token
                        B = oauth2:verify_token(authorization_code,
                                                oauth2_mock_db,
                                                Au, ClientId, RedirectUri),
                        ?assertMatch({ok, [_, _, _]}, B),
                        {_, Prop} = B,
                        AccessToken = proplists:get_value(access_token, Prop),
                        ?assertEqual("Bearer", proplists:get_value(token_type, Prop)),
                        ?assertEqual(7200, proplists:get_value(expires_in, Prop)),
                        ?assertMatch({ok, _}, oauth2:verify_token(access_token,
                                                                  oauth2_mock_db,
                                                                  AccessToken,
                                                                  ClientId)),

                        %%
                        %% Check invalid token
                        ?assertEqual({error, invalid_token},
                                     oauth2:verify_token(access_token,
                                                         oauth2_mock_db,
                                                         Au, ClientId)),

                        %%
                        %% Check invalid call
                        ?assertEqual({error, invalid_token},
                                     oauth2:verify_token(invalid, oauth2_mock_db,
                                                         "123", ClientId, RedirectUri))
                 end
            },
            {"client side (implicit flow) ",
                fun() ->
                        RedirectUri = "http://REDIRECT.URL/here?this=that",
                        Scope = "This That",
                        State = "",
                        State2 = "Just a little state",
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
                        ?assertEqual(7200, T),
                        B = oauth2:verify_token(access_token, oauth2_mock_db,
                                                Au, ClientId),
                        ?assertMatch({ok, _}, B),

                        %%
                        %% Check extra state variable
                        {ok, _, Ru2, _} = oauth2:authorize(token, oauth2_mock_db, ClientId,
                                             RedirectUri, Scope, State2),
                        {_, _, _, Q3, _} = mochiweb_util:urlsplit(Ru2),
                        Q2Prop = mochiweb_util:parse_qs(Q2),
                        Q2WithState = lists:append([[{state, State2}], Q2Prop]),
                        ?assertEqual(Q3, mochiweb_util:urlencode(Q2WithState)),
                        
                        %%
                        %% Check expired token
                        Value = {oauth2,"123abcABC",1330632816,"This That"},
                        Token = "123",
                        oauth2_mock_db:set(access, ClientId++"#"++Token, Value),
                        C = oauth2:verify_token(access_token, oauth2_mock_db,
                                                Token, ClientId),
                        ?assertEqual({error, invalid_token}, C),

                        %%
                        %% Check invalid call
                        ?assertEqual({error, invalid_token},
                                     oauth2:verify_token(invalid, oauth2_mock_db,
                                                         Token, ClientId))
                end 
            }
        ]
    }.

