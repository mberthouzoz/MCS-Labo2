-module(pcap).

%% pcap: pcap library's entry point.

-export([render_file/1]).

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


%% API

render_file(F) ->
  {ok, IO} = open_file(F),
  {ok, PcapHeader} = pcap_header(IO),
  io:format("PcapHeader ~p~n", [PcapHeader]),
  {ok, Parser} = get_type_null(PcapHeader#pcapHeader.network),
  Reader = packet_reader(IO),
  read_data(Reader, Parser, 0).

%% Internals
open_file(F) ->
  file:open(F, [read, binary, raw]).

pcap_header(F) ->
  case read_file(F, 24) of
    <<?PCAP_MAGIC_NATIVE:32/native, Major:16, Minor:16, Thiszone:32, Sigfigs:32, Snaplen:32, Network:32>> ->
      Header = #pcapHeader{magicNumber = ?PCAP_MAGIC_NATIVE, major = Major, minor = Minor, thiszone = Thiszone,
        sigfigs = Sigfigs, snaplen = Snaplen, network = Network},
      {ok, Header};
    {error, Any} -> {error, {bad_header, Any}}
  end.

packet_header(F) ->
  case read_file(F, 16) of
    <<TsSec:32/little, TsUsec:32/little, InclLen:32/little, OrigLen:32/little>> ->
      Header = #packetHeader{tsSec = TsSec, tsUSec = TsUsec, inclLen = InclLen, origLen = OrigLen},
    {ok, Header};
    {error, eof} -> {error, eof};
    Any -> {error, {bad_header, Any}}
  end.

read_data([{error, eof} | _], _, _) -> ok;
read_data([{ok, Header, Payload} | T], Parser, Acc) ->
  io:format("Packet ~p~n", [Acc]),
  io:format("    Header : ~p~n", [Header]),
  io:format("    Payload : ~p~n", [Payload]),
  Packet = Parser(Payload),
  io:format("    Packet : ~p~n", [Packet]),
  read_data(T(), Parser, Acc + 1).


%% Parse paylod from LINKTYPE_NULL
parse_type_null(P) ->
  <<ProtocolFamily:32/native, Rest/binary>> = P,
  io:format("~p~n", [ProtocolFamily]),
  try ProtocolFamily of
    ?FAMILY -> ip_packet(Rest);
    Any -> {error, {unsoported_pf, Any}}
  catch
    error:Any -> {error, Any}
  end.


%% Get only LINKTYPE_NULL
get_type_null(Type) when Type =:= ?NULL_LOOPBACK ->
  {ok, fun(Paylod) -> parse_type_null(Paylod) end}.

%% Read a portion of a file
read_file(F, Len) ->
  case file:read(F, Len) of
    {ok, Data} -> Data;
    {error, Any} -> {error, Any};
    eof -> {error, eof}
  end.


read_packet(F) ->
  case packet_header(F) of
    {ok, Header} ->
      Payload = read_file(F, Header#packetHeader.inclLen),
      {ok, Header, Payload};
    {error, Any} -> {error, Any}
  end.

packet_reader(F) -> [read_packet(F) | fun() -> packet_reader(F) end ].

%% Parse ip packet
%% match and retourn ok or return error
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
      io:format("IHL ~p, Length ~p, OptionLen ~p, PayloadLen ~p, RestLen ~p~nRest :~p~n", [IHL, Length, OptionLen, PayloadLen, byte_size(Rest), Rest]),
      <<Options:OptionLen/binary, RestPayload:PayloadLen/binary>> = Rest,
      IpPacket = #ipHeader{ds = DS, id = Identification, flags = Flags,
        fragmentOffset = FragOffset, ttl = TTL, protocol = Protocol,
        src = SourceIP, dest = DestinationIP,
        options = Options, payload = RestPayload},
      {ok, {ipv4, IpPacket}};
    _ -> {error, ip_payload}
  end.

%% End of Module.