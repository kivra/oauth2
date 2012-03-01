-type uri() :: string().

-record(oauth2, {response_type :: code | token,
                 client_id :: string(),
                 redirect_uri :: uri(),
                 scope :: list(uri()),
                 state :: string(),
                 access_type :: string(),
                 approval_prompt=undefined :: force,
                 code :: string(),
                 client_secret :: string(),
                 grant_type :: string(),
                 access_token :: string(),
                 refresh_token :: string(),
                 expires :: non_neg_integer(),
                 token_type :: string(),
                 error :: atom()
             }).

-record(oauth2_db, {client_id :: string(),
                    expires :: non_neg_integer(),
                    scope :: list(string())
                   }).

