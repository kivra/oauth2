.PHONY: all compile clean eunit dialyze xref

all: deps compile

compile:
	rebar3 compile

clean:
	rebar3 clean

eunit:
	rebar3 eunit

dialyze:
	rebar3 dialyzer

xref:
	rebar3 xref