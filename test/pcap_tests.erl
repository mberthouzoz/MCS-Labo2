%%%-------------------------------------------------------------------
%%% @author Michaël
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 24. mars 2016 12:13
%%%-------------------------------------------------------------------
-module(pcap_tests).
-author("Michaël").

-include_lib("eunit/include/eunit.hrl").

render_test() ->
  A = foobar,
  ?assertEqual(A, pcap:render_file(A)).
