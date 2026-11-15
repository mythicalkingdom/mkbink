unit BinkSocket;

{$mode objfpc}{$H+}

{ Non-blocking, buffered TCP transport for binkp.

  Built on the FPC RTL "sockets" unit (no third party libraries).
  IPv4 only.

  The socket keeps an input and an output buffer.  Send() only queues
  data; Pump() moves bytes between the buffers and the network using
  select(), so a session can read and write "at the same time"
  without ever blocking in a send while the peer is also blocked in a
  send (which would deadlock on large simultaneous transfers). }

interface

uses
  SysUtils,
  Sockets,
  BaseUnix,
  NetDB;

type
  EBinkSocket = class(Exception);

  TBinkSocket = class
  private
    FHandle   : TSocket;
    FInBuf    : array of Byte;
    FInPos    : Integer;
    FInLen    : Integer;
    FOutBuf   : array of Byte;
    FOutPos   : Integer;
    FOutLen   : Integer;
    FClosed   : Boolean;
    FRemote   : String;
    FLastErr  : String;

    procedure SetNonBlocking;
    procedure DoRead;
    procedure DoWrite;
    function  GetAvailable : Integer;
    function  GetOutPending : Integer;

  public
    constructor Create;
    constructor CreateFromHandle(
      AHandle : TSocket;
      const ARemote : String);
    destructor Destroy; override;

    { Originating side: blocking connect with timeout (ms). }
    procedure Connect(
      const Host : String;
      Port : Word;
      TimeoutMs : Integer = 30000);

    { Answering side. }
    procedure Listen(
      Port : Word;
      const BindAddr : String = '';
      Backlog : Integer = 8);

    { Waits up to TimeoutMs for a caller.  Returns nil on timeout. }
    function Accept(TimeoutMs : Integer) : TBinkSocket;

    procedure Disconnect;

    { Queue bytes for sending (never blocks). }
    procedure Send(const Buffer; Len : Integer);

    { Waits up to TimeoutMs for the socket to become readable (or
      writable, when output is queued) and services it.
      Returns False once the connection is closed or failed. }
    function Pump(TimeoutMs : Integer) : Boolean;

    { Blocks until the output buffer is drained or TimeoutMs expires. }
    function Flush(TimeoutMs : Integer) : Boolean;

    { Input buffer access.  Offset is relative to the first unread
      byte. }
    function CopyIn(
      Offset : Integer;
      out Buffer;
      Len : Integer) : Boolean;

    procedure Consume(Len : Integer);

    property Available  : Integer read GetAvailable;
    property OutPending : Integer read GetOutPending;
    property Closed     : Boolean read FClosed;
    property RemoteAddress : String read FRemote;
    property LastError  : String read FLastErr;
  end;

implementation

const
  IO_CHUNK = 65536;

function MonoMs : QWord;
begin
  Result := GetTickCount64;
end;

constructor TBinkSocket.Create;
begin
  inherited Create;

  FHandle := -1;
  FClosed := True;
  FInPos := 0;  FInLen := 0;
  FOutPos := 0; FOutLen := 0;
end;

constructor TBinkSocket.CreateFromHandle(
  AHandle : TSocket;
  const ARemote : String);
begin
  Create;

  FHandle := AHandle;
  FRemote := ARemote;
  FClosed := False;

  SetNonBlocking;
end;

destructor TBinkSocket.Destroy;
begin
  Disconnect;
  inherited Destroy;
end;

procedure TBinkSocket.SetNonBlocking;
var
  Flags : cint;
  One   : cint;
begin
  Flags := fpFcntl(FHandle, F_GETFL);

  if Flags < 0 then
    raise EBinkSocket.Create('fcntl(F_GETFL) failed');

  if fpFcntl(FHandle, F_SETFL, Flags or O_NONBLOCK) < 0 then
    raise EBinkSocket.Create('fcntl(F_SETFL) failed');

  { binkp frames are small; do not let Nagle delay them. }
  One := 1;
  fpSetSockOpt(FHandle, IPPROTO_TCP, TCP_NODELAY, @One, SizeOf(One));
end;

function ResolveIPv4(const Host : String) : TInAddr;
var
  H : THostEntry;
begin
  { Result is in network byte order. }
  Result := StrToNetAddr(Host);

  if Result.s_addr <> 0 then
    Exit;

  if ResolveHostByName(Host, H) then
  begin
    { THostEntry.Addr is in host byte order }
    Result.s_addr := htonl(H.Addr.s_addr);
    if Result.s_addr <> 0 then
      Exit;
  end;

  raise EBinkSocket.CreateFmt(
    'Cannot resolve host "%s"', [Host]);
end;

procedure TBinkSocket.Connect(
  const Host : String;
  Port : Word;
  TimeoutMs : Integer);
var
  Addr   : TInetSockAddr;
  Wr     : TFDSet;
  TV     : TTimeVal;
  R      : cint;
  Err    : cint;
  Len    : TSockLen;
begin
  Disconnect;

  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port   := htons(Port);
  Addr.sin_addr   := ResolveIPv4(Host);

  FHandle := fpSocket(AF_INET, SOCK_STREAM, 0);

  if FHandle < 0 then
    raise EBinkSocket.Create('socket() failed');

  FClosed := False;
  FRemote := Host + ':' + IntToStr(Port);

  SetNonBlocking;

  R := fpConnect(FHandle, @Addr, SizeOf(Addr));

  if R < 0 then
  begin
    if fpGetErrno <> ESysEINPROGRESS then
    begin
      Err := fpGetErrno;
      Disconnect;
      raise EBinkSocket.CreateFmt(
        'Connect to %s:%d failed (errno %d)', [Host, Port, Err]);
    end;

    fpFD_ZERO(Wr);
    fpFD_SET(FHandle, Wr);
    TV.tv_sec  := TimeoutMs div 1000;
    TV.tv_usec := (TimeoutMs mod 1000) * 1000;

    repeat
      R := fpSelect(FHandle + 1, nil, @Wr, nil, @TV);
    until (R >= 0) or (fpGetErrno <> ESysEINTR);

    if R <= 0 then
    begin
      Disconnect;
      raise EBinkSocket.CreateFmt(
        'Connect to %s:%d timed out', [Host, Port]);
    end;

    Err := 0;
    Len := SizeOf(Err);
    fpGetSockOpt(FHandle, SOL_SOCKET, SO_ERROR, @Err, @Len);

    if Err <> 0 then
    begin
      Disconnect;
      raise EBinkSocket.CreateFmt(
        'Connect to %s:%d failed (errno %d)', [Host, Port, Err]);
    end;
  end;
end;

procedure TBinkSocket.Listen(
  Port : Word;
  const BindAddr : String;
  Backlog : Integer);
var
  Addr : TInetSockAddr;
  One  : cint;
begin
  Disconnect;

  FillChar(Addr, SizeOf(Addr), 0);
  Addr.sin_family := AF_INET;
  Addr.sin_port   := htons(Port);

  if BindAddr = '' then
    Addr.sin_addr.s_addr := 0 { INADDR_ANY }
  else
    Addr.sin_addr := ResolveIPv4(BindAddr);

  FHandle := fpSocket(AF_INET, SOCK_STREAM, 0);

  if FHandle < 0 then
    raise EBinkSocket.Create('socket() failed');

  FClosed := False;

  One := 1;
  fpSetSockOpt(FHandle, SOL_SOCKET, SO_REUSEADDR, @One, SizeOf(One));

  if fpBind(FHandle, @Addr, SizeOf(Addr)) < 0 then
  begin
    One := fpGetErrno;
    Disconnect;
    raise EBinkSocket.CreateFmt(
      'Cannot bind port %d (errno %d)', [Port, One]);
  end;

  if fpListen(FHandle, Backlog) < 0 then
  begin
    Disconnect;
    raise EBinkSocket.Create('listen() failed');
  end;

  FRemote := '*:' + IntToStr(Port);
end;

function TBinkSocket.Accept(TimeoutMs : Integer) : TBinkSocket;
var
  Rd   : TFDSet;
  TV   : TTimeVal;
  R    : cint;
  Addr : TInetSockAddr;
  Len  : TSockLen;
  H    : TSocket;
begin
  Result := nil;

  if FClosed then
    Exit;

  fpFD_ZERO(Rd);
  fpFD_SET(FHandle, Rd);
  TV.tv_sec  := TimeoutMs div 1000;
  TV.tv_usec := (TimeoutMs mod 1000) * 1000;

  R := fpSelect(FHandle + 1, @Rd, nil, nil, @TV);

  if R <= 0 then
    Exit;

  Len := SizeOf(Addr);
  H := fpAccept(FHandle, @Addr, @Len);

  if H < 0 then
    Exit;

  Result := TBinkSocket.CreateFromHandle(
    H,
    NetAddrToStr(Addr.sin_addr) + ':' +
      IntToStr(ntohs(Addr.sin_port)));
end;

procedure TBinkSocket.Disconnect;
begin
  if FHandle >= 0 then
  begin
    fpShutdown(FHandle, SHUT_WR);
    fpClose(FHandle);
    FHandle := -1;
  end;

  FClosed := True;
end;

function TBinkSocket.GetAvailable : Integer;
begin
  Result := FInLen - FInPos;
end;

function TBinkSocket.GetOutPending : Integer;
begin
  Result := FOutLen - FOutPos;
end;

procedure TBinkSocket.Send(const Buffer; Len : Integer);
begin
  if Len <= 0 then
    Exit;

  if FOutPos > 0 then
  begin
    { compact }
    if FOutLen > FOutPos then
      Move(FOutBuf[FOutPos], FOutBuf[0], FOutLen - FOutPos);

    Dec(FOutLen, FOutPos);
    FOutPos := 0;
  end;

  if FOutLen + Len > Length(FOutBuf) then
    SetLength(FOutBuf, (FOutLen + Len) * 2);

  Move(Buffer, FOutBuf[FOutLen], Len);
  Inc(FOutLen, Len);

  if not FClosed then
    DoWrite; { opportunistic, non-blocking }
end;

procedure TBinkSocket.DoRead;
var
  R : TSsize;
begin
  if FInPos > 0 then
  begin
    if FInLen > FInPos then
      Move(FInBuf[FInPos], FInBuf[0], FInLen - FInPos);

    Dec(FInLen, FInPos);
    FInPos := 0;
  end;

  if Length(FInBuf) - FInLen < IO_CHUNK then
    SetLength(FInBuf, FInLen + IO_CHUNK * 2);

  R := fpRecv(FHandle, @FInBuf[FInLen], IO_CHUNK, 0);

  if R > 0 then
    Inc(FInLen, R)
  else if R = 0 then
  begin
    FClosed := True;
    FLastErr := 'Connection closed by remote';
  end
  else
  begin
    if (fpGetErrno <> ESysEAGAIN) and
       (fpGetErrno <> ESysEINTR) then
    begin
      FClosed := True;
      FLastErr := 'recv() failed, errno ' + IntToStr(fpGetErrno);
    end;
  end;
end;

procedure TBinkSocket.DoWrite;
var
  R : TSsize;
begin
  while (FOutLen > FOutPos) and (not FClosed) do
  begin
    R := fpSend(FHandle, @FOutBuf[FOutPos],
                FOutLen - FOutPos, MSG_NOSIGNAL);

    if R > 0 then
      Inc(FOutPos, R)
    else if (R < 0) and
            ((fpGetErrno = ESysEAGAIN) or
             (fpGetErrno = ESysEINTR)) then
      Break
    else
    begin
      FClosed := True;
      FLastErr := 'send() failed, errno ' + IntToStr(fpGetErrno);
      Break;
    end;
  end;

  if FOutPos >= FOutLen then
  begin
    FOutPos := 0;
    FOutLen := 0;
  end;
end;

function TBinkSocket.Pump(TimeoutMs : Integer) : Boolean;
var
  Rd, Wr : TFDSet;
  TV     : TTimeVal;
  R      : cint;
  WrP    : PFDSet;
begin
  if FClosed then
    Exit(False);

  fpFD_ZERO(Rd);
  fpFD_SET(FHandle, Rd);

  if FOutLen > FOutPos then
  begin
    fpFD_ZERO(Wr);
    fpFD_SET(FHandle, Wr);
    WrP := @Wr;
  end
  else
    WrP := nil;

  if TimeoutMs < 0 then
    TimeoutMs := 0;

  TV.tv_sec  := TimeoutMs div 1000;
  TV.tv_usec := (TimeoutMs mod 1000) * 1000;

  R := fpSelect(FHandle + 1, @Rd, WrP, nil, @TV);

  if R > 0 then
  begin
    if fpFD_ISSET(FHandle, Rd) <> 0 then
      DoRead;

    if (WrP <> nil) and (not FClosed) and
       (fpFD_ISSET(FHandle, Wr) <> 0) then
      DoWrite;
  end
  else if (R < 0) and (fpGetErrno <> ESysEINTR) then
  begin
    FClosed := True;
    FLastErr := 'select() failed';
  end;

  Result := not FClosed;
end;

function TBinkSocket.Flush(TimeoutMs : Integer) : Boolean;
var
  Deadline : QWord;
  Left     : Int64;
begin
  Deadline := MonoMs + QWord(TimeoutMs);

  while (FOutLen > FOutPos) and (not FClosed) do
  begin
    Left := Int64(Deadline) - Int64(MonoMs);

    if Left <= 0 then
      Break;

    if Left > 200 then
      Left := 200;

    Pump(Left);
  end;

  Result := FOutLen <= FOutPos;
end;

function TBinkSocket.CopyIn(
  Offset : Integer;
  out Buffer;
  Len : Integer) : Boolean;
begin
  Result := (Offset >= 0) and (Len >= 0) and
            (FInLen - FInPos >= Offset + Len);

  if Result and (Len > 0) then
    Move(FInBuf[FInPos + Offset], Buffer, Len);
end;

procedure TBinkSocket.Consume(Len : Integer);
begin
  Inc(FInPos, Len);

  if FInPos >= FInLen then
  begin
    FInPos := 0;
    FInLen := 0;
  end;
end;

end.
