.PHONY: all deps compile clean test ct build-plt dialyze

all: deps compile

deps:
	rebar3 get-deps

compile:
	rebar3 compile

clean:
	rebar3 clean
	rm -f test/*.beam
	rm -f erl_crash.dump

test: ct dialyze

test-build:
	rebar3 compile

ct: clean deps test-build
	rebar3 eunit skip_deps=true

dialyze: clean deps test-build
	rebar3 dialyzer
