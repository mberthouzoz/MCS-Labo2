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

non_existing_file_test() ->
  ?assertEqual({error, enoent}, pcap:open_file("nonexistent")).

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

icmp_type_test() -> [
  {
    ?assertEqual("Echo (ping) reply", pcap:icmp_type_int_to_txt(0))
  }, {
    ?assertEqual("Echo (ping) request", pcap:icmp_type_int_to_txt(8))
  }, {
    ?assertEqual("Other", pcap:icmp_type_int_to_txt(2))
  }
].

icmp_protocol_test() -> [
  {
    ?assertEqual("ICMP", pcap:icmp_protocol_int_to_txt(1))
  }, {
    ?assertEqual("OTHER", pcap:icmp_protocol_int_to_txt(2))
  }
].
