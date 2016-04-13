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
  pcap:render_file("../data/ping.pcap"),
  ?assert(true).

render_verbose_test() ->
  pcap:render_file("../data/ping.pcap", ['V']),
  ?assert(true).

result_from_ping_pcap_test() ->
  {ok, Expected} = file:read_file("../data/ping.txt"),
  {ok, Expr} = pcap:render_file("../data/ping.pcap"),
  ?assertEqual(binary_to_list(Expected), lists:flatten(Expr)).

result_from_ping_pcap_verbose_test() ->
  {ok, Expected} = file:read_file("../data/pingVerbose.txt"),
  {ok, Expr} = pcap:render_file("../data/ping.pcap", ['V']),
  ?assertEqual(binary_to_list(Expected), lists:flatten(Expr)).

