REBAR = ./rebar

.PHONY: all compile deps test doc clean distclean start

all: compile

compile: deps
	@$(REBAR) compile

deps:
	@$(REBAR) get-deps

test: compile
	@$(REBAR) eunit skip_deps=true

doc:
	@$(REBAR) doc skip_deps=true

clean:
	@$(REBAR) clean

distclean: clean
	@$(REBAR) delete-deps
	-@rmdir deps

start: compile
	erl \
	-pa ebin -pa deps/*/ebin \
	-config priv/app.config \
	-s oauth2_example
