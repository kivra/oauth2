ERL ?= erl
APP := oauth2

.PHONY: deps test

all: deps compile

compile:
	@./rebar compile

debug:
	@./rebar debug_info=1 compile

deps:
	@./rebar get-deps

app:
	@./rebar compile skip_deps=true

clean:
	@./rebar clean

distclean: clean
	@./rebar delete-deps

test:
	@./rebar compile skip_deps=true eunit

docs:
	@erl -noshell -run edoc_run application '$(APP)' '"."' '[]'

