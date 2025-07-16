.PHONY: ci clean test eunit dialyze xref

ci: clean xref dialyze test

test: clean eunit

clean:
	rebar3 clean
	rm -f test/*.beam
	rm -f erl_crash.dump

eunit:
	rebar3 eunit

dialyze:
	rebar3 dialyzer

xref:
	rebar3 xref

