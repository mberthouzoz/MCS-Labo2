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

simple_test() ->
  pcap:render_file("../data/ping.pcap"),
  ?assert(true).

