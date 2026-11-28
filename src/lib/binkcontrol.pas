{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkControl;

{$mode objfpc}{$H+}

{ The mailer's control socket: a Unix stream socket (mode 600) that a monitor
  (mkmon for the MK BBS) connects to.

  Everything is lines of text.  The mailer sends a STATE frame (see
  BinkMailer) and LOG lines, and answers each command line with one line
  starting with ACK (done) or ERR (refused).  Commands:

      POLL <address>     call the link now (ignores its retry wait and a hold)
      POLL *             call every link that has mail waiting, now
      HOLD <address>     do not call the link until FREE (until a restart)
      FREE <address>
      RESCAN             look at the outbound for mail again now
      RELOAD             read the settings file again
      ABORT <id>         end a session (the id is in the SESS lines)
      PING

  The unit only moves bytes; BinkMailer decides what they mean.  Nothing here
  blocks: a client that does not read is dropped. }

interface

uses
  Classes,
  SysUtils;

type
  TBinkControlCommand = function(const Cmd : String) : String of object;
  TBinkControlHello   = function : String of object;

  TBinkControl = class
  private
    FPath    : String;
    FListen  : LongInt;
    FClients : array of record
      Fd   : LongInt;
      InBuf  : String;
      OutBuf : String;
      Dead   : Boolean;
    end;
    FOnCommand : TBinkControlCommand;
    FOnHello   : TBinkControlHello;

    procedure DropClient(I : Integer);
    procedure Flush(I : Integer);
    procedure AddOut(I : Integer; const S : String);
    procedure AcceptNew;
    procedure ReadClient(I : Integer);
    function  GetCount : Integer;

  public
    constructor Create(const APath : String);
    destructor Destroy; override;

    { Creates the socket.  False (and Error) when that is not possible. }
    function Start(out Error : String) : Boolean;
    procedure Stop;

    { Accepts, reads commands (answering them), writes what is queued. }
    procedure Tick;

    { Text for every client (each line ends with #10). }
    procedure Broadcast(const S : String);

    property ClientCount : Integer read GetCount;
    property OnCommand : TBinkControlCommand read FOnCommand write FOnCommand;
    property OnHello : TBinkControlHello read FOnHello write FOnHello;
  end;

implementation

uses
  BaseUnix,
  Sockets;

const
  FD_CLOEXEC = 1;
  MAX_OUT = 512 * 1024;
  MAX_IN  = 4096;

constructor TBinkControl.Create(const APath : String);
begin
  inherited Create;
  FPath := APath;
  FListen := -1;
end;

destructor TBinkControl.Destroy;
begin
  Stop;
  inherited Destroy;
end;

function TBinkControl.GetCount : Integer;
begin
  Result := Length(FClients);
end;

function TBinkControl.Start(out Error : String) : Boolean;
var
  A : TUnixSockAddr;
  Old : TMode;
begin
  Result := False;
  Error := '';

  if Length(FPath) > 100 then
  begin
    Error := 'control socket path is too long: ' + FPath;
    Exit;
  end;

  FListen := fpSocket(AF_UNIX, SOCK_STREAM, 0);
  fpFcntl(FListen, F_SETFD, FD_CLOEXEC);   { not inherited by a command we run }

  if FListen < 0 then
  begin
    Error := 'socket: error ' + IntToStr(fpGetErrno);
    Exit;
  end;

  fpFcntl(FListen, F_SETFL, fpFcntl(FListen, F_GETFL) or O_NONBLOCK);
  DeleteFile(FPath);                      { a stale one from a dead mailer }
  FillChar(A, SizeOf(A), 0);
  A.family := AF_UNIX;
  Move(FPath[1], A.path, Length(FPath));
  Old := fpUmask(&177);

  if fpBind(FListen, @A, SizeOf(A)) <> 0 then
  begin
    fpUmask(Old);
    Error := 'cannot create ' + FPath + ' (error ' + IntToStr(fpGetErrno) + ')';
    fpClose(FListen);
    FListen := -1;
    Exit;
  end;

  fpUmask(Old);

  if fpListen(FListen, 4) <> 0 then
  begin
    Error := 'listen: error ' + IntToStr(fpGetErrno);
    fpClose(FListen);
    FListen := -1;
    DeleteFile(FPath);
    Exit;
  end;

  Result := True;
end;

procedure TBinkControl.Stop;
var
  I : Integer;
begin
  for I := High(FClients) downto 0 do
    DropClient(I);

  if FListen >= 0 then
  begin
    fpClose(FListen);
    FListen := -1;
    DeleteFile(FPath);
  end;
end;

procedure TBinkControl.DropClient(I : Integer);
var
  J : Integer;
begin
  fpClose(FClients[I].Fd);

  for J := I to High(FClients) - 1 do
    FClients[J] := FClients[J + 1];

  SetLength(FClients, Length(FClients) - 1);
end;

procedure TBinkControl.AddOut(I : Integer; const S : String);
begin
  FClients[I].OutBuf := FClients[I].OutBuf + S;
end;

procedure TBinkControl.Flush(I : Integer);
var
  N : TSsize;
begin
  while Length(FClients[I].OutBuf) > 0 do
  begin
    N := fpSend(FClients[I].Fd, @FClients[I].OutBuf[1],
      Length(FClients[I].OutBuf), MSG_NOSIGNAL);

    if N > 0 then
      Delete(FClients[I].OutBuf, 1, N)
    else
    begin
      if (N < 0) and (fpGetErrno <> ESysEAGAIN) then
        FClients[I].Dead := True;

      Break;
    end;
  end;
end;

procedure TBinkControl.AcceptNew;
var
  C : LongInt;
  K : Integer;
begin
  while True do
  begin
    C := fpAccept(FListen, nil, nil);
    fpFcntl(C, F_SETFD, FD_CLOEXEC);   { not inherited by a command we run }

    if C < 0 then
      Exit;

    fpFcntl(C, F_SETFL, fpFcntl(C, F_GETFL) or O_NONBLOCK);
    K := Length(FClients);
    SetLength(FClients, K + 1);
    FClients[K].Fd := C;
    FClients[K].InBuf := '';
    FClients[K].OutBuf := '';
    FClients[K].Dead := False;

    if Assigned(FOnHello) then
      AddOut(K, FOnHello());

    Flush(K);
  end;
end;

procedure TBinkControl.ReadClient(I : Integer);
var
  Buf : array[0..1023] of Char;
  N   : TSsize;
  P   : Integer;
  Line, Reply : String;
begin
  while True do
  begin
    N := fpRecv(FClients[I].Fd, @Buf[0], SizeOf(Buf), MSG_NOSIGNAL);

    if N = 0 then
    begin
      FClients[I].Dead := True;
      Exit;
    end;

    if N < 0 then
    begin
      if fpGetErrno <> ESysEAGAIN then
        FClients[I].Dead := True;

      Exit;
    end;

    SetString(Line, PChar(@Buf[0]), N);
    FClients[I].InBuf := FClients[I].InBuf + Line;

    if Length(FClients[I].InBuf) > MAX_IN then
    begin
      FClients[I].Dead := True;
      Exit;
    end;

    repeat
      P := Pos(#10, FClients[I].InBuf);

      if P = 0 then
        Break;

      Line := Trim(Copy(FClients[I].InBuf, 1, P - 1));
      Delete(FClients[I].InBuf, 1, P);

      if Line = '' then
        Continue;

      if Assigned(FOnCommand) then
        Reply := FOnCommand(Line)
      else
        Reply := 'ERR no commands';

      AddOut(I, Reply + #10);
    until False;
  end;
end;

procedure TBinkControl.Tick;
var
  I : Integer;
begin
  if FListen < 0 then
    Exit;

  AcceptNew;

  for I := High(FClients) downto 0 do
  begin
    if not FClients[I].Dead then
      ReadClient(I);

    if not FClients[I].Dead then
      Flush(I);

    if FClients[I].Dead or (Length(FClients[I].OutBuf) > MAX_OUT) then
      DropClient(I);
  end;
end;

procedure TBinkControl.Broadcast(const S : String);
var
  I : Integer;
begin
  for I := 0 to High(FClients) do
    if not FClients[I].Dead then
      AddOut(I, S);
end;

end.
