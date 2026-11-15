unit BinkListener;

{$mode objfpc}{$H+}

{ Accepts incoming binkp calls and runs an answering session for each
  of them in its own thread, so several systems can call at once.

  At most MaxSessions sessions run at a time; any further caller is
  told "M_BSY Too many sessions" and disconnected.

  Programs using this unit must be built with threads enabled; on
  Unix that means putting the "cthreads" unit first in the program's
  uses clause.  OnLog, OnSession and OnSessionDone are called from
  the session threads, so they must be thread safe. }

interface

uses
  Classes,
  SysUtils,
  BinkTypes,
  BinkSocket,
  BinkFrame,
  BinkProtocol,
  BinkSession,
  BinkInbound;

const
  BINK_DEFAULT_MAX_SESSIONS = 8;

type
  TBinkSessionEvent = procedure(
    Sender : TObject;
    Session : TBinkSession) of object;

  TBinkListener = class;

  TBinkSessionThread = class(TThread)
  private
    FOwner : TBinkListener;
    FSock  : TBinkSocket;
    FId    : Integer;

  protected
    procedure Execute; override;

  public
    constructor Create(
      AOwner : TBinkListener;
      ASock  : TBinkSocket;
      AId    : Integer);
  end;

  TBinkListener = class
  private
    FConfig   : TBinkConfig;
    FInbound  : TBinkInbound;
    FPort     : Word;
    FBindAddr : String;
    FStopped  : Boolean;
    FMax      : Integer;
    FNextId   : Integer;
    FLock     : TRTLCriticalSection;
    FThreads  : TFPList;   { TBinkSessionThread }
    FSessions : TFPList;   { TBinkSession currently running }

    FOnLog         : TBinkLogEvent;
    FOnSession     : TBinkSessionEvent;
    FOnSessionDone : TBinkSessionEvent;

    procedure Log(const Msg : String);
    procedure Register(S : TBinkSession);
    procedure Unregister(S : TBinkSession);
    procedure CancelAll;
    procedure Reap(All : Boolean);
    function  GetActive : Integer;

  public
    constructor Create(
      const AConfig : TBinkConfig;
      AInbound : TBinkInbound;
      APort : Word = BINK_DEFAULT_PORT;
      const ABindAddr : String = '');
    destructor Destroy; override;

    { Listens and serves callers until Stop is called, then cancels
      the running sessions and waits for their threads. }
    procedure Run;

    { Safe to call from a signal handler: only sets a flag, which Run
      notices within half a second. }
    procedure Stop;

    property MaxSessions : Integer
      read FMax write FMax;

    property ActiveSessions : Integer
      read GetActive;

    property OnLog : TBinkLogEvent
      read FOnLog write FOnLog;

    { Fired in the session's thread for each new caller, before the
      session starts: assign OnAuth / OnAuthenticated / Bso /
      Outbound on Session here. }
    property OnSession : TBinkSessionEvent
      read FOnSession write FOnSession;

    property OnSessionDone : TBinkSessionEvent
      read FOnSessionDone write FOnSessionDone;
  end;

implementation

{ ------------------------------------------------------------------ }

constructor TBinkSessionThread.Create(
  AOwner : TBinkListener;
  ASock  : TBinkSocket;
  AId    : Integer);
begin
  FOwner := AOwner;
  FSock  := ASock;
  FId    := AId;

  { we join and free the threads ourselves }
  FreeOnTerminate := False;

  inherited Create(False);
end;

procedure TBinkSessionThread.Execute;
var
  Sess : TBinkSession;
begin
  Sess := nil;

  try
    Sess := TBinkSession.Create(FOwner.FConfig);
    Sess.Inbound   := FOwner.FInbound;
    Sess.OnLog     := FOwner.FOnLog;
    Sess.LogPrefix := Format('[#%d] ', [FId]);

    FOwner.Register(Sess);

    try
      if Assigned(FOwner.FOnSession) then
        FOwner.FOnSession(FOwner, Sess);

      Sess.Answer(FSock);

      if Assigned(FOwner.FOnSessionDone) then
        FOwner.FOnSessionDone(FOwner, Sess);
    finally
      FOwner.Unregister(Sess);
    end;
  except
    on E : Exception do
      FOwner.Log(Format('[#%d] Session error: %s', [FId, E.Message]));
  end;

  Sess.Free;
  FSock.Free;
end;

{ ------------------------------------------------------------------ }

constructor TBinkListener.Create(
  const AConfig : TBinkConfig;
  AInbound : TBinkInbound;
  APort : Word;
  const ABindAddr : String);
begin
  inherited Create;

  FConfig   := AConfig;
  FInbound  := AInbound;
  FPort     := APort;
  FBindAddr := ABindAddr;
  FMax      := BINK_DEFAULT_MAX_SESSIONS;

  InitCriticalSection(FLock);
  FThreads  := TFPList.Create;
  FSessions := TFPList.Create;
end;

destructor TBinkListener.Destroy;
begin
  CancelAll;
  Reap(True);

  FSessions.Free;
  FThreads.Free;
  DoneCriticalSection(FLock);

  inherited Destroy;
end;

procedure TBinkListener.Log(const Msg : String);
begin
  if Assigned(FOnLog) then
    FOnLog(Msg);
end;

procedure TBinkListener.Register(S : TBinkSession);
begin
  EnterCriticalSection(FLock);
  try
    FSessions.Add(S);

    { shutting down already: do not start }
    if FStopped then
      S.Cancel;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TBinkListener.Unregister(S : TBinkSession);
begin
  EnterCriticalSection(FLock);
  try
    FSessions.Remove(S);
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TBinkListener.CancelAll;
var
  I : Integer;
begin
  EnterCriticalSection(FLock);
  try
    for I := 0 to FSessions.Count - 1 do
      TBinkSession(FSessions[I]).Cancel;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

{ Joins and frees threads whose session has ended (or all of them). }
procedure TBinkListener.Reap(All : Boolean);
var
  I : Integer;
  T : TBinkSessionThread;
begin
  for I := FThreads.Count - 1 downto 0 do
  begin
    T := TBinkSessionThread(FThreads[I]);

    if All or T.Finished then
    begin
      T.WaitFor;
      T.Free;
      FThreads.Delete(I);
    end;
  end;
end;

function TBinkListener.GetActive : Integer;
begin
  Reap(False);
  Result := FThreads.Count;
end;

procedure TBinkListener.Stop;
begin
  FStopped := True;
end;

procedure TBinkListener.Run;
var
  Server : TBinkSocket;
  Client : TBinkSocket;
  T      : TBinkSessionThread;
begin
  FStopped := False;

  Server := TBinkSocket.Create;
  try
    Server.Listen(FPort, FBindAddr);
    Log(Format('Listening on %s (up to %d sessions at a time)',
      [Server.RemoteAddress, FMax]));

    while not FStopped do
    begin
      Client := Server.Accept(500);

      if Client = nil then
        Continue;

      if GetActive >= FMax then
      begin
        Log('Refusing ' + Client.RemoteAddress +
          ': too many sessions (M_BSY)');

        try
          SendCommand(Client, M_BSY, 'Too many sessions');
          Client.Flush(1000);
        except
          { caller already gone }
        end;

        Client.Free;
        Continue;
      end;

      Inc(FNextId);

      try
        T := TBinkSessionThread.Create(Self, Client, FNextId);
        FThreads.Add(T);
      except
        on E : Exception do
        begin
          Log('Cannot start session thread: ' + E.Message);
          Client.Free;
        end;
      end;
    end;

    Log('Stopping: waiting for ' + IntToStr(GetActive) +
      ' active session(s)');

    CancelAll;
    Reap(True);

    Log('Listener stopped');
  finally
    Server.Free;
  end;
end;

end.
