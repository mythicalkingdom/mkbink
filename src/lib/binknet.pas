Unit BinkNet;   {TCP over IPv4 and IPv6: connect, listen, addresses as text.  The same as MKNet.pas of the MK BBS (mk-fpc/src), which has the tests (tests/nettest.pas): keep them in step}

{$MODE OBJFPC}
{$H+}

{
     One place for the socket work that the listener and the hub clients share.  Names are resolved with getaddrinfo of the C library, literal addresses are read and written
     with inet_pton / inet_ntop, so IPv4 and IPv6 are handled the same way and nothing depends on what this FPC's Sockets unit knows.

     An address as text is the usual form: 192.0.2.7 or 2001:db8::7.  An IPv4 caller on a dual stack socket is written as 192.0.2.7 (not ::ffff:192.0.2.7) and a zone
     (fe80::1%eth0) is cut off, so one machine is one address for the counts, the login guard, the log and the monitor.
}

Interface

Function NetConnect(Const Host: String; Port: Word; TimeoutMs: Integer; Out Fd: LongInt; Out Err: String): Boolean;
  {a connected, blocking socket: every address of Host (a name or a literal address) is tried in turn, each for TimeoutMs}

Function NetListen(Const Bind: String; Port: Word; Out Fd: LongInt; Out What: String): Boolean;
  {a socket that listens.  Bind '' or '::' = IPv4 and IPv6 on one socket (IPV6_V6ONLY off), IPv4 only when the system has no IPv6; '0.0.0.0' = IPv4 only; any other
   literal address = that address.  What says what was done (for the log) or why not.}

Function NetPeer(Fd: LongInt): String;        {the address of the other end, normalised; '' when it is not known}
Function NetLocal(Fd: LongInt): String;       {the address of this end}
Function NetPeerPort(Fd: LongInt): Word;      {the port of the other end, 0 when it is not known}
Function NetNormalise(Const Addr: String): String;
Function NetFamily(Const Addr: String): Integer;       {4, 6, or 0 when it is no address}
Function NetMatch(Const Addr, Entry: String): Boolean;
  {Addr is the address Entry or inside the net Entry (a.b.c.d/n, or an IPv6 address and /n)}
Function NetIsLoopback(Const Addr: String): Boolean;   {127.x.x.x or ::1}
Function NetHasIPv6: Boolean;                          {this system can make an IPv6 socket and bind ::1}
Function NetSplitHostPort(Const S: String; Out Host: String; Out Port: Integer): Boolean;
  {host, host:port, [v6]:port, [v6] or a bare IPv6 address; Port is -1 when there is none; False for something that is not one of these}
Function NetJoinHostPort(Const Host: String; Port: Integer): String;      {host:port, [v6]:port}


Implementation

Uses SysUtils, BaseUnix, Sockets, ctypes;

Const
  AF_INET6_ = 10;
  IPPROTO_IPV6_ = 41;
  IPV6_V6ONLY_ = 26;
  AI_NUMERICHOST_ = 4;

Type
  PAddrInfo = ^TAddrInfo;
  TAddrInfo = Record                   {glibc and musl order}
    ai_flags, ai_family, ai_socktype, ai_protocol: cint;
    ai_addrlen: cuint;
    ai_addr: Pointer;
    ai_canonname: PChar;
    ai_next: PAddrInfo;
  End;

  TStorage = Array[0..127] Of Byte;

Function getaddrinfo(node, service: PChar; hints: PAddrInfo; Var res: PAddrInfo): cint; cdecl; external 'c' name 'getaddrinfo';
Procedure freeaddrinfo(res: PAddrInfo); cdecl; external 'c' name 'freeaddrinfo';
Function gai_strerror(code: cint): PChar; cdecl; external 'c' name 'gai_strerror';
Function inet_pton(af: cint; src: PChar; dst: Pointer): cint; cdecl; external 'c' name 'inet_pton';
Function inet_ntop(af: cint; src: Pointer; dst: PChar; size: cuint): PChar; cdecl; external 'c' name 'inet_ntop';


Function Binary(Const Addr: String; Out Bytes: Array Of Byte): Integer;
  {the address as 4 or 16 bytes; 4, 6 or 0 (not an address)}
  Var
    S: String;
    p: Integer;

  Begin
  Binary := 0;
  S := Trim(Addr);
  p := Pos('%', S);
  If p > 0 Then
    S := Copy(S, 1, p - 1);
  If S = '' Then
    Exit;
  If Pos(':', S) > 0 Then
    Begin
    If inet_pton(AF_INET6_, PChar(S), @Bytes[0]) = 1 Then
      Binary := 6;
    End
  Else If inet_pton(AF_INET, PChar(S), @Bytes[0]) = 1 Then
    Binary := 4;
  End;


Function Text(Family: Integer; Const Bytes): String;
  Var
    Buf: Array[0..63] Of Char;

  Begin
  Text := '';
  If Family = 4 Then
    Begin
    If inet_ntop(AF_INET, @Bytes, @Buf[0], SizeOf(Buf)) <> Nil Then
      Text := StrPas(@Buf[0]);
    End
  Else If inet_ntop(AF_INET6_, @Bytes, @Buf[0], SizeOf(Buf)) <> Nil Then
    Text := StrPas(@Buf[0]);
  End;


Function V4Mapped(Const B: Array Of Byte): Boolean;
  Var
    i: Integer;

  Begin
  V4Mapped := False;
  For i := 0 To 9 Do
    If B[i] <> 0 Then
      Exit;
  V4Mapped := (B[10] = $FF) And (B[11] = $FF);
  End;


Function NetNormalise(Const Addr: String): String;
  Var
    B: Array[0..15] Of Byte;
    F: Integer;

  Begin
  FillChar(B, SizeOf(B), 0);
  F := Binary(Addr, B);
  If F = 0 Then
    NetNormalise := Addr
  Else If (F = 6) And V4Mapped(B) Then
    NetNormalise := Text(4, B[12])
  Else
    NetNormalise := Text(F, B);
  End;


Function NetFamily(Const Addr: String): Integer;
  Var
    B: Array[0..15] Of Byte;
    F: Integer;

  Begin
  FillChar(B, SizeOf(B), 0);
  F := Binary(Addr, B);
  If (F = 6) And V4Mapped(B) Then
    F := 4;
  NetFamily := F;
  End;


Function Octets(Const Addr: String; Out B: Array Of Byte): Integer;
  {the normalised address as bytes: 4 (IPv4, also a mapped one) or 16}
  Var
    T: Array[0..15] Of Byte;
    F: Integer;

  Begin
  FillChar(T, SizeOf(T), 0);
  F := Binary(Addr, T);
  Octets := 0;
  If F = 4 Then
    Begin
    Move(T[0], B[0], 4);
    Octets := 4;
    End
  Else If F = 6 Then
    Begin
    If V4Mapped(T) Then
      Begin
      Move(T[12], B[0], 4);
      Octets := 4;
      End
    Else
      Begin
      Move(T[0], B[0], 16);
      Octets := 16;
      End;
    End;
  End;


Function NetMatch(Const Addr, Entry: String): Boolean;
  Var
    A, E: Array[0..15] Of Byte;
    NA, NE, Bits, p, i, Whole, Rest: Integer;
    Net: String;

  Begin
  NetMatch := False;
  p := Pos('/', Entry);
  If p = 0 Then
    Net := Entry
  Else
    Net := Copy(Entry, 1, p - 1);
  NA := Octets(Addr, A);
  NE := Octets(Net, E);
  If (NA = 0) Or (NE = 0) Or (NA <> NE) Then
    Exit;
  If p = 0 Then
    Bits := NA * 8
  Else
    Begin
    Bits := StrToIntDef(Copy(Entry, p + 1, 4), -1);
    If (Bits < 0) Or (Bits > NA * 8) Then
      Exit;
    End;
  Whole := Bits Div 8;
  Rest := Bits Mod 8;
  For i := 0 To Whole - 1 Do
    If A[i] <> E[i] Then
      Exit;
  If Rest > 0 Then
    If ((A[Whole] Xor E[Whole]) And ($FF Shl (8 - Rest)) And $FF) <> 0 Then
      Exit;
  NetMatch := True;
  End;


Function NetIsLoopback(Const Addr: String): Boolean;
  Begin
  NetIsLoopback := NetMatch(Addr, '127.0.0.0/8') Or NetMatch(Addr, '::1');
  End;


Function NetSplitHostPort(Const S: String; Out Host: String; Out Port: Integer): Boolean;
  Var
    T, P: String;
    p1, Colons, i: Integer;

  Begin
  NetSplitHostPort := False;
  Host := '';
  Port := -1;
  T := Trim(S);
  If T = '' Then
    Exit;
  If T[1] = '[' Then
    Begin
    p1 := Pos(']', T);
    If p1 = 0 Then
      Exit;
    Host := Copy(T, 2, p1 - 2);
    P := Copy(T, p1 + 1, 20);
    If P <> '' Then
      Begin
      If P[1] <> ':' Then
        Exit;
      Port := StrToIntDef(Copy(P, 2, 10), -1);
      If (Port < 0) Or (Port > 65535) Then
        Exit;
      End;
    NetSplitHostPort := Host <> '';
    Exit;
    End;
  Colons := 0;
  For i := 1 To Length(T) Do
    If T[i] = ':' Then
      Inc(Colons);
  If Colons <= 1 Then
    Begin
    p1 := Pos(':', T);
    If p1 = 0 Then
      Host := T
    Else
      Begin
      Host := Copy(T, 1, p1 - 1);
      Port := StrToIntDef(Copy(T, p1 + 1, 10), -1);
      If (Port < 0) Or (Port > 65535) Then
        Exit;
      End;
    NetSplitHostPort := Host <> '';
    End
  Else
    Begin
    Host := T;                         {a bare IPv6 address}
    NetSplitHostPort := NetFamily(T) = 6;
    End;
  End;


Function NetJoinHostPort(Const Host: String; Port: Integer): String;
  Begin
  If Pos(':', Host) > 0 Then
    NetJoinHostPort := '[' + Host + ']:' + IntToStr(Port)
  Else
    NetJoinHostPort := Host + ':' + IntToStr(Port);
  End;


Function AddrText(P: Pointer; Len: cuint): String;
  Var
    S: ^TStorage;
    F: Integer;
    B: Array[0..15] Of Byte;

  Begin
  AddrText := '';
  S := P;
  If Len < 2 Then
    Exit;
  F := PWord(S)^;
  If F = AF_INET Then
    Begin
    Move(S^[4], B[0], 4);
    AddrText := Text(4, B);
    End
  Else If F = AF_INET6_ Then
    Begin
    Move(S^[8], B[0], 16);
    AddrText := NetNormalise(Text(6, B));
    End;
  End;


Function NetPeer(Fd: LongInt): String;
  Var
    S: TStorage;
    L: TSockLen;

  Begin
  L := SizeOf(S);
  FillChar(S, SizeOf(S), 0);
  If fpGetPeerName(Fd, @S, @L) = 0 Then
    NetPeer := AddrText(@S, L)
  Else
    NetPeer := '';
  End;


Function NetPeerPort(Fd: LongInt): Word;
  Var
    S: TStorage;
    L: TSockLen;

  Begin
  L := SizeOf(S);
  FillChar(S, SizeOf(S), 0);
  If (fpGetPeerName(Fd, @S, @L) = 0) And (L >= 4) Then
    NetPeerPort := (S[2] Shl 8) Or S[3]
  Else
    NetPeerPort := 0;
  End;


Function NetLocal(Fd: LongInt): String;
  Var
    S: TStorage;
    L: TSockLen;

  Begin
  L := SizeOf(S);
  FillChar(S, SizeOf(S), 0);
  If fpGetSockName(Fd, @S, @L) = 0 Then
    NetLocal := AddrText(@S, L)
  Else
    NetLocal := '';
  End;


Function TryConnect(Ai: PAddrInfo; TimeoutMs: Integer; Out Fd: LongInt; Out Code: Integer): Boolean;
  {Code when it fails: 0 = no answer in time, -1 = no socket for that family, else the errno of the connect}
  Var
    Flags, Res, SoErr: LongInt;
    L: TSockLen;
    P: TPollFd;

  Begin
  TryConnect := False;
  Code := 0;
  Fd := fpSocket(Ai^.ai_family, SOCK_STREAM, 0);
  If Fd < 0 Then
    Begin
    Code := -1;
    Exit;
    End;
  Flags := fpFcntl(Fd, F_GETFL);
  fpFcntl(Fd, F_SETFL, Flags Or O_NONBLOCK);
  Res := fpConnect(Fd, Ai^.ai_addr, Ai^.ai_addrlen);
  If (Res < 0) And (fpGetErrno <> ESysEINPROGRESS) Then
    Begin
    Code := fpGetErrno;
    fpClose(Fd);
    Fd := -1;
    Exit;
    End;
  If Res < 0 Then
    Begin
    P.fd := Fd;
    P.events := POLLOUT;
    P.revents := 0;
    If fpPoll(@P, 1, TimeoutMs) <= 0 Then
      Begin
      Code := 0;
      fpClose(Fd);
      Fd := -1;
      Exit;
      End;
    SoErr := 0;
    L := SizeOf(SoErr);
    fpGetSockOpt(Fd, SOL_SOCKET, SO_ERROR, @SoErr, @L);
    If SoErr <> 0 Then
      Begin
      Code := SoErr;
      fpClose(Fd);
      Fd := -1;
      Exit;
      End;
    End;
  fpFcntl(Fd, F_SETFL, Flags);
  TryConnect := True;
  End;


Function NetConnect(Const Host: String; Port: Word; TimeoutMs: Integer; Out Fd: LongInt; Out Err: String): Boolean;
  Var
    Hints: TAddrInfo;
    Res, Ai: PAddrInfo;
    Rc: cint;
    H, Where: String;
    Code: Integer;

  Begin
  NetConnect := False;
  Fd := -1;
  Err := '';
  H := Host;
  If (Length(H) > 1) And (H[1] = '[') And (H[Length(H)] = ']') Then
    H := Copy(H, 2, Length(H) - 2);
  FillChar(Hints, SizeOf(Hints), 0);
  Hints.ai_family := AF_UNSPEC;
  Hints.ai_socktype := SOCK_STREAM;
  Res := Nil;
  Rc := getaddrinfo(PChar(H), PChar(IntToStr(Port)), @Hints, Res);
  If (Rc <> 0) Or (Res = Nil) Then
    Begin
    Err := 'Unknown host ' + Host;
    Exit;
    End;
  Try
    Code := -1;
    Ai := Res;
    While Ai <> Nil Do
      Begin
      If TryConnect(Ai, TimeoutMs, Fd, Code) Then
        Begin
        NetConnect := True;
        Exit;
        End;
      Ai := Ai^.ai_next;
      End;
    Where := NetJoinHostPort(H, Port);
    If Code = 0 Then
      Err := 'No answer from ' + Where
    Else If Code = ESysECONNREFUSED Then
      Err := 'Connection refused by ' + Where
    Else
      Err := 'Cannot connect to ' + Where + ' (error ' + IntToStr(Code) + ')';       {of the last address tried}
  Finally
    freeaddrinfo(Res);
  End;
  End;


Function NetListen(Const Bind: String; Port: Word; Out Fd: LongInt; Out What: String): Boolean;
  Var
    A4: TInetSockAddr;
    A6: Array[0..27] Of Byte;            {sockaddr_in6}
    One, Zero: LongInt;
    B: Array[0..15] Of Byte;
    F: Integer;
    Want: String;
    V6: Boolean;

  Procedure Fail(Const Why: String);
    Begin
    What := Why;
    If Fd >= 0 Then
      fpClose(Fd);
    Fd := -1;
    End;

  Begin
  NetListen := False;
  Fd := -1;
  What := '';
  Want := Bind;
  If (Want = '') Or (Want = '::') Or (Want = '*') Then
    Want := '::';
  FillChar(B, SizeOf(B), 0);
  F := 0;
  If Want <> '::' Then
    Begin
    F := Binary(Want, B);
    If F = 0 Then
      Begin
      What := 'bad bind address ' + Bind;
      Exit;
      End;
    End;
  V6 := (Want = '::') Or (F = 6);
  One := 1;
  Zero := 0;
  If V6 Then
    Begin
    Fd := fpSocket(AF_INET6_, SOCK_STREAM, 0);
    If Fd < 0 Then
      Begin
      If (Want = '::') And ((fpGetErrno = ESysEAFNOSUPPORT) Or (fpGetErrno = ESysEPROTONOSUPPORT)) Then
        V6 := False                      {no IPv6 in this kernel: IPv4 only}
      Else
        Begin
        What := 'no IPv6 socket (error ' + IntToStr(fpGetErrno) + ')';
        Exit;
        End;
      End;
    End;
  If V6 Then
    Begin
    fpSetSockOpt(Fd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));
    If Want = '::' Then
      fpSetSockOpt(Fd, IPPROTO_IPV6_, IPV6_V6ONLY_, @Zero, SizeOf(Zero))
    Else
      fpSetSockOpt(Fd, IPPROTO_IPV6_, IPV6_V6ONLY_, @One, SizeOf(One));
    FillChar(A6, SizeOf(A6), 0);
    PWord(@A6[0])^ := AF_INET6_;
    A6[2] := Hi(Port);                   {network order}
    A6[3] := Lo(Port);
    If Want <> '::' Then
      Move(B[0], A6[8], 16);
    If fpBind(Fd, @A6, SizeOf(A6)) <> 0 Then
      Begin
      Fail('cannot bind ' + NetJoinHostPort(Bind, Port) + ' (error ' + IntToStr(fpGetErrno) + ')');
      Exit;
      End;
    If Want = '::' Then
      What := '[::]:' + IntToStr(Port) + ' (IPv4 and IPv6)'
    Else
      What := NetJoinHostPort(NetNormalise(Want), Port) + ' (IPv6)';
    End
  Else
    Begin
    Fd := fpSocket(AF_INET, SOCK_STREAM, 0);
    If Fd < 0 Then
      Begin
      What := 'no socket (error ' + IntToStr(fpGetErrno) + ')';
      Exit;
      End;
    fpSetSockOpt(Fd, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));
    FillChar(A4, SizeOf(A4), 0);
    A4.sin_family := AF_INET;
    A4.sin_port := htons(Port);
    If Want = '::' Then
      FillChar(A4.sin_addr, SizeOf(A4.sin_addr), 0)
    Else
      Move(B[0], A4.sin_addr, 4);
    If fpBind(Fd, @A4, SizeOf(A4)) <> 0 Then
      Begin
      Fail('cannot bind ' + NetJoinHostPort(Bind, Port) + ' (error ' + IntToStr(fpGetErrno) + ')');
      Exit;
      End;
    If Want = '::' Then
      What := '0.0.0.0:' + IntToStr(Port) + ' (IPv4 only: this system has no IPv6)'
    Else
      What := NetJoinHostPort(Want, Port) + ' (IPv4)';
    End;
  If fpListen(Fd, 16) <> 0 Then
    Begin
    Fail('listen: error ' + IntToStr(fpGetErrno));
    Exit;
    End;
  NetListen := True;
  End;


Function NetHasIPv6: Boolean;
  Var
    Fd: LongInt;
    What: String;

  Begin
  NetHasIPv6 := False;
  If NetListen('::1', 0, Fd, What) Then
    Begin
    fpClose(Fd);
    NetHasIPv6 := True;
    End;
  End;


End.
