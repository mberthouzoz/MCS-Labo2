%%%-------------------------------------------------------------------
%%% @author Michaël Berthouzoz - Marc Pellet - David Villa
%%% @copyright (C) 2016, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 24. mars 2016 12:13
%%%-------------------------------------------------------------------
-module(pcap).

%% pcap: pcap library's entry point.

-export([render_file/1, render_file/2, icmp_type_int_to_txt/1, icmp_protocol_int_to_txt/1, open_file/1]).

%% Magic Number
-define(PCAP_MAGIC_NATIVE, 16#a1b2c3d4).

%% Null/Loopback
-define(NULL_LOOPBACK, 0).

%% Family IP (2)
-define(FAMILY, 2).

%% IP v4
-define(IP_VERSION, 4).
-define(IP_MIN_HDR_LEN, 5).

%% magic number, major version number, minor version number, GMT to local correction, accuracy of timestamps,
%% max length of captured packets (in octets), data link type
-record(pcapHeader, {magicNumber = ?PCAP_MAGIC_NATIVE, major, minor, thiszone, sigfigs, snaplen, network}).
%% timestamp seconds, timestamp microseconds, number of octets of packet saved in file, actual length of packet
-record(packetHeader, {tsSec, tsUSec, inclLen, origLen}).
-record(ipHeader, {ds, id, flags, fragmentOffset, ttl, protocol, src, dest, options, payload}).
-record(ipAddr, {a, b, c, d}).


%% API

render_file(F) ->
  {ok, IO} = open_file(F),
  {ok, PcapHeader} = pcap_header(IO),
  {ok, Parser} = get_type_null(PcapHeader#pcapHeader.network),
  Reader = packet_reader(IO),
  read_data(Reader, Parser, 1).

render_file(F, O) ->
  case O of
    ['V'] ->
      {ok, IO} = open_file(F),
      {ok, PcapHeader} = pcap_header(IO),
      {ok, Parser} = get_type_null(PcapHeader#pcapHeader.network),
      Reader = packet_reader(IO),
      read_data_verbose(Reader, Parser, 1);
    _ -> {error, option_forbidden}
  end.

%% Internals
open_file(F) ->
  file:open(F, [read, binary, raw]).

%% Parse the pcap header
pcap_header(F) ->
  case read_file(F, 24) of
    <<?PCAP_MAGIC_NATIVE:32/native, Major:16, Minor:16, Thiszone:32, Sigfigs:32, Snaplen:32, Network:32>> ->
      Header = #pcapHeader{magicNumber = ?PCAP_MAGIC_NATIVE, major = Major, minor = Minor, thiszone = Thiszone,
        sigfigs = Sigfigs, snaplen = Snaplen, network = Network},
      {ok, Header};
    {error, Any} -> {error, {bad_header, Any}}
  end.

%% Parse the packet header
packet_header(F) ->
  case read_file(F, 16) of
    <<TsSec:32/little, TsUsec:32/little, InclLen:32/little, OrigLen:32/little>> ->
      Header = #packetHeader{tsSec = TsSec, tsUSec = TsUsec, inclLen = InclLen, origLen = OrigLen},
      {ok, Header};
    {error, eof} -> {error, eof};
    Any -> {error, {bad_header, Any}}
  end.

%% Read data of the packet
read_data([{error, eof} | _], _, _) -> ok;
read_data([{ok, Header, Payload} | T], Parser, Acc) ->
  {ok, Packet} = Parser(Payload),
  <<TypeICMP:8, _/binary>> = Packet#ipHeader.payload,
  Protocol = icmp_protocol_int_to_txt(Packet#ipHeader.protocol),
  Type = icmp_type_int_to_txt(TypeICMP),
  {ok, Src} = addr_format(Packet#ipHeader.src),
  {ok, Dest} = addr_format(Packet#ipHeader.dest),
  io:format("  ~p    ~p.~p.~p.~p -> ~p.~p.~p.~p    ~s ~p ~s ttl=~p~n",
    [Acc, Src#ipAddr.a, Src#ipAddr.b, Src#ipAddr.c, Src#ipAddr.d, Dest#ipAddr.a, Dest#ipAddr.b,
      Dest#ipAddr.c, Dest#ipAddr.d, Protocol, Header#packetHeader.inclLen, Type, Packet#ipHeader.ttl]),
  read_data(T(), Parser, Acc + 1).

%% Read more data of the packet
read_data_verbose([{error, eof} | _], _, _) -> ok;
read_data_verbose([{ok, Header, Payload} | T], Parser, Acc) ->
  {ok, Packet} = Parser(Payload),
  <<TypeICMP:8, Code:8, _/binary>> = Packet#ipHeader.payload,
  io:format("Frame ~p: ~p bytes on wire (~p bits), ~p bytes on captured (~p)~n",
    [Acc, Header#packetHeader.inclLen, 8 * Header#packetHeader.inclLen, Header#packetHeader.origLen,
      Header#packetHeader.origLen * 8]),
  io:format("  Encapsulation type: ~p (15)~n", [get_type_text(?NULL_LOOPBACK)]),
  io:format("  Arrival Time: ~p~n", [Header#packetHeader.tsSec]),
  io:format("  [Epoch Time: ~p seconds]~n", [Header#packetHeader.tsSec]),
  Protocol = icmp_protocol_int_to_txt(Packet#ipHeader.protocol),
  io:format("  Protocol: ~p (~p)~n", [Protocol, Packet#ipHeader.protocol]),
  Type = icmp_type_int_to_txt(TypeICMP),
  io:format("  Type: ~p (~s)~n", [TypeICMP, Type]),
  io:format("  Code: ~p ~n~n", [Code]),
  read_data_verbose(T(), Parser, Acc + 1).


%% Parse paylod from LINKTYPE_NULL
parse_type_null(P) ->
  <<ProtocolFamily:32/native, Rest/binary>> = P,
  case ProtocolFamily of
    ?FAMILY -> ip_packet(Rest);
    Any -> {error, {bad_family, Any}}
  end.


%% Get only LINKTYPE_NULL
get_type_null(Type) when Type =:= ?NULL_LOOPBACK ->
  {ok, fun(Payload) -> parse_type_null(Payload) end}.

%% Read a portion of a file
read_file(F, Len) ->
  case file:read(F, Len) of
    {ok, Data} -> Data;
    {error, Any} -> {error, Any};
    eof -> {error, eof}
  end.

%% Read the packet
read_packet(F) ->
  case packet_header(F) of
    {ok, Header} ->
      Payload = read_file(F, Header#packetHeader.inclLen),
      {ok, Header, Payload};
    {error, Any} -> {error, Any}
  end.

%% Parse ip packet
%% match and return ok or return error
ip_packet(Payload) ->
  case Payload of
    <<?IP_VERSION:4, IHL:4, DS:8/big, Length:16/big,
      Identification:16/big, Flags:3, FragOffset:13/big,
      TTL:8, Protocol:8, _:16,
      SourceIP:4/binary,
      DestinationIP:4/binary,
      Rest/binary>> when IHL >= ?IP_MIN_HDR_LEN ->
      OptionLen = (IHL - ?IP_MIN_HDR_LEN) * 4,
      PayloadLen = (Length - (IHL * 4)),
      <<Options:OptionLen/binary, RestPayload:PayloadLen/binary>> = Rest,
      IpPacket = #ipHeader{ds = DS, id = Identification, flags = Flags,
        fragmentOffset = FragOffset, ttl = TTL, protocol = Protocol,
        src = SourceIP, dest = DestinationIP,
        options = Options, payload = RestPayload},
      {ok, IpPacket};
    _ -> {error, ip_payload}
  end.

packet_reader(F) -> [read_packet(F) | fun() -> packet_reader(F) end].

%% Convert int protocole to string
icmp_protocol_int_to_txt(P) ->
  case P of
    1 -> "ICMP";
    _ -> "OTHER"
  end.

%% Convert int type to string
icmp_type_int_to_txt(T) ->
  case T of
    0 -> "Echo (ping) reply";
    8 -> "Echo (ping) request";
    _ -> "Other"
  end.

%% Transforme address <<127, 0, 0, 1>> to 127.0.0.1
addr_format(Addr) ->
  <<A:8, B:8, C:8, D:8>> = Addr,
  IpAddr = #ipAddr{a = A, b = B, c = C, d = D},
  {ok, IpAddr}.

%% Return type of network
get_type_text(Type) ->
  case Type of
    0 -> "NULL/Loopback";
    _ -> "Other"
  end.

%% End of Module.