PROJECT = oauth2
DIALYZER = dialyzer
REBAR = ./rebar

.PHONY: all deps compile clean test ct build-plt dialyze

all: deps compile

deps:
	$(REBAR) -C rebar.test.config get-deps

compile:
	$(REBAR) compile

clean:
	$(REBAR) clean
	rm -f test/*.beam
	rm -f erl_crash.dump

test: ct dialyze doc

test-build:
	$(REBAR) -C rebar.test.config compile

ct: clean deps test-build
	$(REBAR) -C rebar.test.config eunit skip_deps=true

build-plt:
	$(DIALYZER) --build_plt --output_plt .$(PROJECT).plt \
		--apps erts kernel stdlib sasl inets crypto public_key ssl

dialyze: clean deps test-build
	$(DIALYZER) --plt .$(PROJECT).plt ebin
