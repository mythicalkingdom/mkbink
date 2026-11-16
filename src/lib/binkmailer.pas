unit BinkMailer;

{$mode objfpc}{$H+}

{ The mailer: answers calls and makes them, all from one BinkLinks setup.

  Run starts the listener (a thread of its own), then every second looks at
  the links: a link is called when mail for it is waiting in the BSO outbound
  (hold mail does not count: that is only sent when the link calls us) or when
  its "poll" interval has passed.  A failed call is retried after
  retry-min seconds, doubled for each further failure up to retry-max.  A
  successful one clears the failures.

  Stop and RequestReload only set flags, so a signal handler may call them.
  A reload reads the file again: links, passwords, intervals and retry times
  take effect for the next call or caller.  Our own addresses, paths, port
  and the like are used as they were at the start; a change is reported in the
  log as needing a restart. }

interface

uses
  Classes,
  SysUtils,
  BinkTypes,
  BinkNode,
  BinkLinks,
  BinkSession,
  BinkListener,
  BinkInbound,
  Process,
  BinkBso,
  BinkControl;

type
  { what the mailer knows about one link while it runs }
  TLinkState = class
  public
    Key         : String;        { the address as text }
    Address     : TFTNAddress;
    Active      : Boolean;       { a call is going on }
    Failures    : Integer;       { calls that failed in a row }
    NextAttempt : Int64;         { seconds (NowSec), not before }
    LastPoll    : Int64;         { when the last call ended, -1 = never }
    Waiting     : Boolean;       { mail was waiting at the last look }
    PendCount   : Integer;       { ... how many items, and their size }
    PendBytes   : Int64;
    Held        : Boolean;       { not called until released (control socket) }
    Force       : Boolean;       { call at once (control socket) }
    LastResult  : String;
  end;

  { a session that is going on, for the control socket }
  TSessEntry = class
  public
    Id          : Integer;
    Sess        : TBinkSession;
    Originating : Boolean;
    Start       : Int64;         { unix time }
    P           : TBinkProgress;
  end;

  TSessionEnded = procedure(Session : TBinkSession) of object;

  TPollThread = class(TThread)
  private
    FSession : TBinkSession;
    FInbound : TBinkInbound;
    FInboundUn : TBinkInbound;
    FNode    : TBinkNodeInfo;
    FState   : TLinkState;
    FOk      : Boolean;
    FError   : String;
    FOnEnded : TSessionEnded;
  protected
    procedure Execute; override;
  public
    constructor Create(AState : TLinkState; const ACfg : TBinkConfig;
      const ANode : TBinkNodeInfo; const AInboundPath, AUnsecurePath : String;
      ABso : TBinkBso; ALog : TBinkLogEvent; AOnEnded : TSessionEnded);
    destructor Destroy; override;
    procedure Cancel;
    property Session : TBinkSession read FSession;
    property State : TLinkState read FState;
    property Ok : Boolean read FOk;
    property Error : String read FError;
  end;

  TListenThread = class(TThread)
  private
    FListener : TBinkListener;
    FError    : String;
  protected
    procedure Execute; override;
  public
    constructor Create(AListener : TBinkListener);
    property Error : String read FError;
  end;

  TBinkMailer = class
  private
    FFile      : String;
    FLog       : TBinkLogEvent;
    FSetup     : TBinkSetup;
    FLock      : TRTLCriticalSection;
    FStop      : Boolean;
    FReload    : Boolean;
    FBso       : TBinkBso;
    FInbound   : TBinkInbound;
    FInboundUn : TBinkInbound;
    FHookLock  : TRTLCriticalSection;
    FListener  : TBinkListener;
    FListenThr : TListenThread;
    FStates    : TStringList;       { Key -> TLinkState }
    FPolls     : TFPList;           { TPollThread }
    FLastScan  : Int64;
    FFatal     : Boolean;
    FStartKey  : String;

    { control socket }
    FControlPath : String;
    FControl     : TBinkControl;
    FSessLock    : TRTLCriticalSection;
    FSess        : TFPList;           { TSessEntry }
    FNextId      : Integer;
    FStarted     : Int64;             { unix time }
    FCalls, FCallsOk, FCallsFailed, FInSessions : Integer;
    FTotSent, FTotRecv : Int64;
    FTotFilesSent, FTotFilesRecv : Integer;
    FRing        : TStringList;       { the last log lines, for new clients }
    FPendLog     : String;            { not yet sent to the clients }
    FDirty       : Boolean;
    FLastState   : QWord;

    procedure Log(const Msg : String);
    procedure EmitLog(const Msg : String);
    procedure SessAdd(S : TBinkSession; Orig : Boolean);
    procedure SessProgress(Sender : TObject; const P : TBinkProgress);
    procedure SessRemove(S : TBinkSession);
    procedure RunHook(S : TBinkSession; const Cmd : String; Timeout : Integer);
    procedure InboundDone(Sender : TObject; Session : TBinkSession);
    function  BuildState : String;
    function  Hello : String;
    function  HandleCommand(const Cmd : String) : String;
    procedure ControlTick;
    function  FindLinkState(const Key : String) : TLinkState;
    function  State(Link : TBinkLink) : TLinkState;
    function  LoadSetup(const Path : String; out S : TBinkSetup) : Boolean;
    function  RestartKey(S : TBinkSetup) : String;
    procedure DoReload;
    procedure Describe;
    procedure CheckFileMode;
    procedure Schedule;
    procedure ProbeLink(St : TLinkState);
    procedure StartPoll(Link : TBinkLink; St : TLinkState;
      const Why : String);
    procedure ReapPolls(All : Boolean);
    procedure PollDone(T : TPollThread);
    function  Auth(const Remote : TFTNAddress;
                out Password : String) : Boolean;
    procedure NewSession(Sender : TObject; Session : TBinkSession);
    function  ActivePolls : Integer;
  public
    constructor Create(const ASetupFile : String; ALog : TBinkLogEvent);
    destructor Destroy; override;

    { A Unix socket to make in Run (see BinkControl); '' = none. }
    property ControlPath : String read FControlPath write FControlPath;

    { Runs until Stop.  Result: 0 = stopped, 1 = could not start / fatal. }
    function Run : Integer;

    procedure Stop;
    procedure RequestReload;
  end;

function NowSec : Int64;
function UnixNow : Int64;

{ z:n/f, with .p only for a point }

function FmtAddr(const A : TFTNAddress) : String;

{ Seconds to wait after Failures failed calls in a row (1 = the first). }
function BackoffSeconds(Failures, RetryMin, RetryMax : Integer) : Integer;


implementation

uses
  {$IFDEF UNIX}
  BaseUnix,
  {$ENDIF}
  DateUtils,
  BinkOutbound;

function Clean(const S : String) : String;
var
  I : Integer;
begin
  Result := S;

  for I := 1 to Length(Result) do
    if Result[I] in [#9, #10, #13] then
      Result[I] := ' ';
end;

function NowSec : Int64;
begin
  Result := GetTickCount64 div 1000;
end;

function FmtAddr(const A : TFTNAddress) : String;
begin
  Result := Format('%d:%d/%d', [A.Zone, A.Net, A.Node]);

  if A.Point <> 0 then
    Result := Result + '.' + IntToStr(A.Point);
end;

function UnixNow : Int64;
begin
  Result := DateTimeToUnix(Now, False);
end;

function BackoffSeconds(Failures, RetryMin, RetryMax : Integer) : Integer;
var
  I : Integer;
  V : Int64;
begin
  V := RetryMin;

  for I := 2 to Failures do
  begin
    V := V * 2;

    if V >= RetryMax then
      Break;
  end;

  if V > RetryMax then
    V := RetryMax;

  Result := V;
end;

{ ------------------------------------------------------------------ }

constructor TPollThread.Create(AState : TLinkState; const ACfg : TBinkConfig;
  const ANode : TBinkNodeInfo; const AInboundPath, AUnsecurePath : String;
  ABso : TBinkBso; ALog : TBinkLogEvent; AOnEnded : TSessionEnded);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FOnEnded := AOnEnded;
  FState := AState;
  FNode := ANode;
  FInbound := TBinkInbound.Create(AInboundPath);
  FSession := TBinkSession.Create(ACfg);
  FSession.Inbound := FInbound;

  if AUnsecurePath <> '' then
  begin
    FInboundUn := TBinkInbound.Create(AUnsecurePath);
    FSession.InboundUnsecure := FInboundUn;
  end;

  FSession.Bso := ABso;
  FSession.OnLog := ALog;
  FSession.LogPrefix := '[poll ' + FmtAddr(ANode.Address) + '] ';
end;

destructor TPollThread.Destroy;
begin
  FSession.Free;
  FInbound.Free;
  FInboundUn.Free;
  inherited Destroy;
end;

procedure TPollThread.Execute;
begin
  try
    FOk := FSession.Originate(FNode);
  except
    on E : Exception do
    begin
      FOk := False;
      FError := E.Message;
    end;
  end;

  if Assigned(FOnEnded) then
    FOnEnded(FSession);
end;

procedure TPollThread.Cancel;
begin
  FSession.Cancel;
end;

constructor TListenThread.Create(AListener : TBinkListener);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FListener := AListener;
end;

procedure TListenThread.Execute;
begin
  try
    FListener.Run;
  except
    on E : Exception do
      FError := E.Message;
  end;
end;

{ ------------------------------------------------------------------ }

constructor TBinkMailer.Create(const ASetupFile : String;
  ALog : TBinkLogEvent);
begin
  inherited Create;
  FFile := ASetupFile;
  FLog := ALog;
  InitCriticalSection(FLock);
  FStates := TStringList.Create;
  FStates.Sorted := True;
  FStates.OwnsObjects := True;
  FPolls := TFPList.Create;
  InitCriticalSection(FSessLock);
  InitCriticalSection(FHookLock);
  FSess := TFPList.Create;
  FRing := TStringList.Create;
end;

destructor TBinkMailer.Destroy;
begin
  FRing.Free;
  FSess.Free;
  DoneCriticalSection(FSessLock);
  DoneCriticalSection(FHookLock);
  FPolls.Free;
  FStates.Free;
  FSetup.Free;
  DoneCriticalSection(FLock);
  inherited Destroy;
end;

procedure TBinkMailer.Log(const Msg : String);
begin
  EmitLog(Msg);
end;

{ every log line: out, into the ring for clients that connect later, and
  queued for the clients that are connected now }
procedure TBinkMailer.EmitLog(const Msg : String);
var
  L : String;
  I : Integer;
begin
  if Assigned(FLog) then
    FLog(Msg);

  L := Msg;

  for I := 1 to Length(L) do
    if L[I] in [#9, #10, #13] then
      L[I] := ' ';

  L := IntToStr(UnixNow) + #9 + L;

  EnterCriticalSection(FSessLock);
  try
    FRing.Add(L);

    while FRing.Count > 200 do
      FRing.Delete(0);

    if FControl <> nil then
      FPendLog := FPendLog + 'LOG ' + L + #10;

    FDirty := True;
  finally
    LeaveCriticalSection(FSessLock);
  end;
end;

procedure TBinkMailer.Stop;
begin
  FStop := True;
end;

procedure TBinkMailer.RequestReload;
begin
  FReload := True;
end;

function TBinkMailer.State(Link : TBinkLink) : TLinkState;
var
  I : Integer;
  K : String;
begin
  K := FmtAddr(Link.Address);
  I := FStates.IndexOf(K);

  if I >= 0 then
    Exit(TLinkState(FStates.Objects[I]));

  Result := TLinkState.Create;
  Result.Key := K;
  Result.Address := Link.Address;
  Result.LastPoll := -1;
  FStates.AddObject(K, Result);
end;

function TBinkMailer.LoadSetup(const Path : String;
  out S : TBinkSetup) : Boolean;
var
  Errs, Warns : TStringList;
  I : Integer;
begin
  Errs := TStringList.Create;
  Warns := TStringList.Create;
  S := TBinkSetup.Create;
  try
    Result := S.LoadFromFile(Path, Errs, Warns);

    for I := 0 to Warns.Count - 1 do
      Log('Settings warning: ' + Warns[I]);

    for I := 0 to Errs.Count - 1 do
      Log('Settings error: ' + Errs[I]);

    if not Result then
      FreeAndNil(S);
  finally
    Warns.Free;
    Errs.Free;
  end;
end;

{ everything that is only read at the start }
function TBinkMailer.RestartKey(S : TBinkSetup) : String;
var
  I : Integer;
begin
  Result := '';

  for I := 0 to High(S.Addresses) do
    Result := Result + FmtAddr(S.Addresses[I]) + ' ';

  Result := Result + Format('|%s|%s|%s|%s|%s|%s|%d|%s|%d|%s|%d|%d|%d|%s|%s',
    [S.Domain, S.SysName, S.Sysop, S.Location, S.Inbound + '>' + S.InboundUnsecure, S.Bso, S.Zone,
     BoolToStr(S.Listen, True), S.Port, S.Bind, S.MaxSessions, S.MaxPolls,
     S.Timeout, BoolToStr(S.RequireCram, True),
     BoolToStr(S.Plz, True) + BoolToStr(S.Nr, True)]);
end;

procedure TBinkMailer.Describe;
var
  I : Integer;
  L : TBinkLink;
  S : String;
begin
  S := '';

  for I := 0 to High(FSetup.Addresses) do
    S := S + ' ' + FmtAddr(FSetup.Addresses[I]);

  Log('Our address(es):' + S);
  Log('Inbound: ' + FSetup.Inbound + '   BSO outbound: ' +
    FSetup.Bso + '   default zone ' + IntToStr(FSetup.BsoZone));

  if FSetup.InboundUnsecure <> '' then
    Log('Inbound without password: ' + FSetup.InboundUnsecure);

  if FSetup.OnInbound <> '' then
    Log('After received files: ' + FSetup.OnInbound);

  if FSetup.Listen then
    Log(Format('Listening on %s:%d (up to %d callers)',
      [FSetup.Bind + Copy('*', 1, Ord(FSetup.Bind = '')), FSetup.Port,
       FSetup.MaxSessions]))
  else
    Log('Not listening (listen no)');

  for I := 0 to FSetup.LinkCount - 1 do
  begin
    L := FSetup.Links[I];

    if L.AnswerOnly then
      S := 'answers only'
    else if L.Host = '' then
      S := 'no host: cannot be called'
    else
      S := Format('%s:%d, %s', [L.Host, L.Port,
        Copy('poll every ' + IntToStr(L.PollMin) + ' min', 1,
          100 * Ord(L.PollMin > 0)) + Copy('call when mail waits', 1,
          100 * Ord(L.PollMin = 0))]);

    Log(Format('Link %s %s: %s', [FmtAddr(L.Address), L.Name, S]));
  end;
end;

procedure TBinkMailer.CheckFileMode;
{$IFDEF UNIX}
var
  St : Stat;
  I : Integer;
  Pw : Boolean;
begin
  Pw := FSetup.Password <> '';

  for I := 0 to FSetup.LinkCount - 1 do
    if FSetup.Links[I].Password <> '' then
      Pw := True;

  if Pw and (fpStat(FFile, St) = 0) and ((St.st_mode and &077) <> 0) then
    Log('WARNING: ' + FFile + ' holds passwords and others can read it; ' +
      'use chmod 600');
end;
{$ELSE}
begin
end;
{$ENDIF}

{ ------------------------------------------------------------------ }

function TBinkMailer.Auth(const Remote : TFTNAddress;
  out Password : String) : Boolean;
var
  L : TBinkLink;
begin
  Result := False;
  Password := '';
  EnterCriticalSection(FLock);
  try
    L := FSetup.FindLink(Remote);

    if L <> nil then
    begin
      Password := L.Password;
      Result := True;
    end
    else if FSetup.AcceptUnknown then
    begin
      Password := FSetup.Password;
      Result := True;
    end;
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure TBinkMailer.NewSession(Sender : TObject; Session : TBinkSession);
begin
  Session.OnAuth := @Auth;
  SessAdd(Session, False);

  if FBso <> nil then
    Session.Bso := FBso;
end;

function TBinkMailer.ActivePolls : Integer;
begin
  Result := FPolls.Count;
end;

{ ------------------------------------------------------------------ }

procedure TBinkMailer.StartPoll(Link : TBinkLink; St : TLinkState;
  const Why : String);
var
  Node : TBinkNodeInfo;
  Cfg  : TBinkConfig;
  T    : TPollThread;
begin
  Node := Default(TBinkNodeInfo);
  Node.Address := Link.Address;
  Node.Host := Link.Host;
  Node.Port := Link.Port;
  Node.Password := Link.Password;
  Cfg := FSetup.SessionConfig(Link);

  Log(Format('Calling %s %s at %s:%d (%s)',
    [FmtAddr(Link.Address), Link.Name, Link.Host, Link.Port, Why]));

  T := TPollThread.Create(St, Cfg, Node, FSetup.Inbound,
    FSetup.InboundUnsecure, FBso, @EmitLog, @SessRemove);
  St.Active := True;
  St.Force := False;
  Inc(FCalls);
  SessAdd(T.Session, True);
  FPolls.Add(T);
  FDirty := True;
  T.Start;
end;

procedure TBinkMailer.ProbeLink(St : TLinkState);
begin
  try
    St.PendCount := 0;
    St.PendBytes := 0;

    if FBso <> nil then
      St.PendCount := FBso.PendingInfo(St.Address, False, St.PendBytes);

    St.Waiting := St.PendCount > 0;
  except
    on E : Exception do
    begin
      St.Waiting := False;
      Log('Outbound error for ' + St.Key + ': ' + E.Message);
    end;
  end;
end;

procedure TBinkMailer.Schedule;
var
  I : Integer;
  L : TBinkLink;
  St : TLinkState;
  Now_ : Int64;
  ScanDue, Due : Boolean;
  Why : String;
begin
  Now_ := NowSec;
  ScanDue := (FLastScan = 0) or (Now_ - FLastScan >= FSetup.ScanInterval);

  if ScanDue then
    FLastScan := Now_;

  for I := 0 to FSetup.LinkCount - 1 do
  begin
    L := FSetup.Links[I];

    if L.AnswerOnly or (L.Host = '') then
      Continue;

    St := State(L);

    if St.Active then
      Continue;

    if ScanDue then
      ProbeLink(St);

    if St.Force then
    begin
      if ActivePolls < FSetup.MaxPolls then
        StartPoll(L, St, 'poll requested');

      Continue;
    end;

    if St.Held or (Now_ < St.NextAttempt) then
      Continue;

    Due := False;

    if St.Waiting then
    begin
      Due := True;
      Why := 'mail waiting';
    end
    else if (L.PollMin > 0) and
            ((St.LastPoll < 0) or (Now_ - St.LastPoll >= L.PollMin * 60)) then
    begin
      Due := True;
      Why := 'scheduled';
    end;

    if Due and (ActivePolls < FSetup.MaxPolls) then
      StartPoll(L, St, Why);
  end;
end;

procedure TBinkMailer.PollDone(T : TPollThread);
var
  St : TLinkState;
  Wait : Integer;
  Left : Integer;
begin
  St := T.State;
  St.Active := False;
  St.LastPoll := NowSec;
  St.Waiting := False;

  FDirty := True;

  if T.Ok then
  begin
    Inc(FCallsOk);
    St.Failures := 0;
    St.LastResult := 'ok';
    St.NextAttempt := 0;
    Log('Call to ' + St.Key + ' finished');

    { mail the remote did not take: do not call again at once }
    Left := 0;

    if FBso <> nil then
      try
        Left := FBso.Pending(St.Address, False);
      except
        Left := 0;
      end;

    if Left > 0 then
    begin
      St.NextAttempt := NowSec + FSetup.RetryMin;
      Log(Format('%d item(s) still waiting for %s; next call in %d s',
        [Left, St.Key, FSetup.RetryMin]));
    end;
  end
  else
  begin
    Inc(FCallsFailed);
    Inc(St.Failures);
    Wait := BackoffSeconds(St.Failures, FSetup.RetryMin, FSetup.RetryMax);
    St.NextAttempt := NowSec + Wait;
    St.LastResult := T.Error;

    if St.LastResult = '' then
      St.LastResult := T.Session.LastError;

    if St.LastResult = '' then
      St.LastResult := 'failed';

    if T.Error <> '' then
      Log('Call to ' + St.Key + ' failed: ' + T.Error);

    Log(Format('Call to %s failed (%d in a row); retry in %d s',
      [St.Key, St.Failures, Wait]));
  end;
end;

procedure TBinkMailer.ReapPolls(All : Boolean);
var
  I : Integer;
  T : TPollThread;
begin
  for I := FPolls.Count - 1 downto 0 do
  begin
    T := TPollThread(FPolls[I]);

    if All then
      T.Cancel;

    if All or T.Finished then
    begin
      T.WaitFor;
      FPolls.Delete(I);
      PollDone(T);
      T.Free;
    end;
  end;
end;

{ ------------------------------------------------------------------ }

procedure TBinkMailer.DoReload;
var
  S, Old : TBinkSetup;
begin
  Log('Reading ' + FFile + ' again');

  if not LoadSetup(FFile, S) then
  begin
    Log('The settings file has errors: the old settings stay in use');
    Exit;
  end;

  if RestartKey(S) <> FStartKey then
    Log('NOTE: addresses, paths, port or session options changed; ' +
      'these are used after a restart');

  EnterCriticalSection(FLock);
  try
    Old := FSetup;
    FSetup := S;
  finally
    LeaveCriticalSection(FLock);
  end;

  Old.Free;
  FLastScan := 0;
  Log(Format('Settings loaded: %d link(s)', [FSetup.LinkCount]));
end;


{ ------------------------------------------------------------------ }
{ Sessions going on, and the control socket                           }
{ ------------------------------------------------------------------ }

procedure TBinkMailer.SessAdd(S : TBinkSession; Orig : Boolean);
var
  E : TSessEntry;
begin
  E := TSessEntry.Create;
  E.Sess := S;
  E.Originating := Orig;
  E.Start := UnixNow;
  E.P := Default(TBinkProgress);
  E.P.Originating := Orig;

  EnterCriticalSection(FSessLock);
  try
    Inc(FNextId);
    E.Id := FNextId;
    FSess.Add(E);
    FDirty := True;
  finally
    LeaveCriticalSection(FSessLock);
  end;

  S.OnProgress := @SessProgress;
end;

procedure TBinkMailer.SessProgress(Sender : TObject; const P : TBinkProgress);
var
  I : Integer;
begin
  EnterCriticalSection(FSessLock);
  try
    for I := 0 to FSess.Count - 1 do
      if TSessEntry(FSess[I]).Sess = Sender then
      begin
        TSessEntry(FSess[I]).P := P;
        Break;
      end;
  finally
    LeaveCriticalSection(FSessLock);
  end;
end;

{ Called by the session's own thread when it is over, before the session is
  freed, so an entry always has a live session. }
procedure TBinkMailer.SessRemove(S : TBinkSession);
var
  I : Integer;
  E : TSessEntry;
  Cmd : String;
  Tmo : Integer;
begin
  EnterCriticalSection(FSessLock);
  try
    for I := FSess.Count - 1 downto 0 do
    begin
      E := TSessEntry(FSess[I]);

      if E.Sess = S then
      begin
        Inc(FTotSent, S.BytesSent);
        Inc(FTotRecv, S.BytesReceived);
        Inc(FTotFilesSent, S.FilesSent);
        Inc(FTotFilesRecv, S.FilesReceived);

        if not E.Originating then
          Inc(FInSessions);

        FSess.Delete(I);
        E.Free;
        FDirty := True;
        Break;
      end;
    end;
  finally
    LeaveCriticalSection(FSessLock);
  end;

  if S.Received.Count > 0 then
  begin
    EnterCriticalSection(FLock);
    try
      Cmd := FSetup.OnInbound;
      Tmo := FSetup.HookTimeout;
    finally
      LeaveCriticalSection(FLock);
    end;

    if Cmd <> '' then
      RunHook(S, Cmd, Tmo);
  end;
end;

{ The command named by on-inbound, run without a shell with the paths of the
  files this session received as its arguments, and in its environment
    MKBINK_REMOTE   the remote's addresses
    MKBINK_SECURE   1 if the remote used a password, else 0
    MKBINK_ORIG     1 if we called, 0 if it called us
    MKBINK_FILES    the number of files
  One at a time (a tosser does not want two of itself); killed after the
  timeout.  Its output goes into the log. }
procedure TBinkMailer.RunHook(S : TBinkSession; const Cmd : String;
  Timeout : Integer);
var
  P     : TProcess;
  Parts : TStringList;
  I     : Integer;
  Buf   : String;
  Got   : LongInt;
  Start : QWord;
  Rest  : String;
  Killed : Boolean;

  procedure Flush(All : Boolean);
  var
    K : Integer;
    L : String;
  begin
    repeat
      K := Pos(#10, Rest);

      if K = 0 then
      begin
        if All and (Rest <> '') then
        begin
          Log('[hook] ' + Clean(Rest));
          Rest := '';
        end;

        Break;
      end;

      L := Copy(Rest, 1, K - 1);
      Delete(Rest, 1, K);
      Log('[hook] ' + Clean(L));
    until False;
  end;

  procedure Drain;
  begin
    while P.Output.NumBytesAvailable > 0 do
    begin
      SetLength(Buf, 4096);
      Got := P.Output.Read(Buf[1], 4096);

      if Got <= 0 then
        Break;

      Rest := Rest + Copy(Buf, 1, Got);
    end;

    Flush(False);
  end;

begin
  EnterCriticalSection(FHookLock);
  Parts := TStringList.Create;
  P := TProcess.Create(nil);
  Rest := '';
  Killed := False;
  try
    try
      CommandToList(Cmd, Parts);

      if Parts.Count = 0 then
        Exit;

      P.Executable := Parts[0];

      for I := 1 to Parts.Count - 1 do
        P.Parameters.Add(Parts[I]);

      for I := 0 to S.Received.Count - 1 do
        P.Parameters.Add(S.Received[I]);

      for I := 1 to GetEnvironmentVariableCount do
        P.Environment.Add(GetEnvironmentString(I));

      P.Environment.Add('MKBINK_REMOTE=' + S.RemoteAddresses);
      P.Environment.Add('MKBINK_SECURE=' + IntToStr(Ord(S.Secure)));
      P.Environment.Add('MKBINK_ORIG=' + IntToStr(Ord(S.Originating)));
      P.Environment.Add('MKBINK_FILES=' + IntToStr(S.Received.Count));
      P.Options := [poUsePipes, poStderrToOutPut, poNoConsole];

      Log(Format('Running %s (%d file(s) from %s)',
        [Parts[0], S.Received.Count, S.RemoteAddresses]));
      P.Execute;
      Start := GetTickCount64;

      while P.Running do
      begin
        Drain;

        if (GetTickCount64 - Start) > QWord(Timeout) * 1000 then
        begin
          Killed := True;
          P.Terminate(9);
          Break;
        end;

        Sleep(50);
      end;

      P.WaitOnExit;
      Drain;
      Flush(True);

      if Killed then
        Log('[hook] killed after ' + IntToStr(Timeout) + ' s')
      else if P.ExitStatus <> 0 then
        Log('[hook] exit status ' + IntToStr(P.ExitStatus))
      else
        Log('[hook] done');
    except
      on E : Exception do
        Log('[hook] cannot run ' + Cmd + ': ' + E.Message);
    end;
  finally
    P.Free;
    Parts.Free;
    LeaveCriticalSection(FHookLock);
  end;
end;

procedure TBinkMailer.InboundDone(Sender : TObject; Session : TBinkSession);
begin
  SessRemove(Session);
end;

function TBinkMailer.FindLinkState(const Key : String) : TLinkState;
var
  I : Integer;
begin
  Result := nil;
  I := FStates.IndexOf(Key);

  if I >= 0 then
    Result := TLinkState(FStates.Objects[I]);
end;

{ The whole picture, as lines between STATE and END (tab separated):

    STATE <unix time now>
    ME    addresses \t system name \t sysop \t started \t listen port (0 = no) \t version
    STAT  calls made \t ok \t failed \t calls answered \t bytes sent \t received \t files sent \t received
    LINK  address \t name \t host:port \t flags (A answers only, H held) \t poll min \t state \t failures \t
          next call (unix, 0 = now / not planned) \t last result \t items waiting \t bytes waiting \t last call (unix, 0 = never)
    SESS  id \t O|I \t remote addresses \t system \t sysop \t location \t start \t state \t options \t
          bytes sent \t received \t files sent \t received \t sending \t pos \t size \t receiving \t pos \t size
    END }
function TBinkMailer.BuildState : String;
var
  I : Integer;
  L : TBinkLink;
  St : TLinkState;
  E : TSessEntry;
  S, Fl, Stt, Opts, Dir, Next : String;
  U, NextU : Int64;
  PortN : Integer;
  Names : String;

const
  STATE_NAMES : array[TBinkState] of String =
    ('connecting', 'connected', 'authenticating', 'transfer',
     'finishing', 'done');
begin
  U := UnixNow;
  Result := 'STATE ' + IntToStr(U) + #10;
  Names := '';

  for I := 0 to High(FSetup.Addresses) do
  begin
    if Names <> '' then
      Names := Names + ' ';

    Names := Names + FmtAddr(FSetup.Addresses[I]);
  end;

  if FSetup.Listen then
    PortN := FSetup.Port
  else
    PortN := 0;

  Result := Result + 'ME ' + Names + #9 + Clean(FSetup.SysName) + #9 +
    Clean(FSetup.Sysop) + #9 + IntToStr(FStarted) + #9 + IntToStr(PortN) +
    #9 + BINK_VERSION_STRING + #10;

  EnterCriticalSection(FSessLock);
  try
    Result := Result + Format('STAT %d'#9'%d'#9'%d'#9'%d'#9'%d'#9'%d'#9'%d'#9'%d'#10,
      [FCalls, FCallsOk, FCallsFailed, FInSessions, FTotSent, FTotRecv,
       FTotFilesSent, FTotFilesRecv]);

    for I := 0 to FSess.Count - 1 do
    begin
      E := TSessEntry(FSess[I]);

      if E.Originating then
        Dir := 'O'
      else
        Dir := 'I';

      Opts := '';

      if E.P.Secure then Opts := Opts + 'secure ';
      if E.P.Plz then Opts := Opts + 'plz ';
      if E.P.Nr then Opts := Opts + 'nr ';

      Result := Result + Format('SESS %d'#9'%s'#9'%s'#9'%s'#9'%s'#9'%s'#9'%d'#9 +
        '%s'#9'%s'#9'%d'#9'%d'#9'%d'#9'%d'#9'%s'#9'%d'#9'%d'#9'%s'#9'%d'#9'%d'#10,
        [E.Id, Dir, Clean(E.P.Remote), Clean(E.P.SysName), Clean(E.P.Sysop),
         Clean(E.P.Location), E.Start, STATE_NAMES[E.P.State], Trim(Opts),
         E.P.BytesSent, E.P.BytesReceived, E.P.FilesSent, E.P.FilesReceived,
         Clean(E.P.TxName), E.P.TxPos, E.P.TxSize,
         Clean(E.P.RxName), E.P.RxPos, E.P.RxSize]);
    end;
  finally
    LeaveCriticalSection(FSessLock);
  end;

  for I := 0 to FSetup.LinkCount - 1 do
  begin
    L := FSetup.Links[I];
    St := State(L);
    Fl := '';

    if L.AnswerOnly then Fl := Fl + 'A';
    if St.Held then Fl := Fl + 'H';

    if L.AnswerOnly then
      Stt := 'answer'
    else if L.Host = '' then
      Stt := 'nohost'
    else if St.Active then
      Stt := 'calling'
    else if St.Held then
      Stt := 'held'
    else if (St.Failures > 0) and (St.NextAttempt > NowSec) then
      Stt := 'retry'
    else if St.Waiting then
      Stt := 'waiting'
    else
      Stt := 'idle';

    NextU := 0;

    if (not L.AnswerOnly) and (L.Host <> '') and (not St.Active) then
    begin
      if St.NextAttempt > NowSec then
        NextU := U + (St.NextAttempt - NowSec)
      else if (L.PollMin > 0) and (St.LastPoll >= 0) then
        NextU := U + (St.LastPoll + L.PollMin * 60 - NowSec);
    end;

    if St.LastPoll >= 0 then
      Next := IntToStr(U - (NowSec - St.LastPoll))
    else
      Next := '0';

    Result := Result + Format('LINK %s'#9'%s'#9'%s'#9'%s'#9'%d'#9'%s'#9'%d'#9 +
      '%d'#9'%s'#9'%d'#9'%d'#9'%s'#10,
      [FmtAddr(L.Address), Clean(L.Name),
       Clean(L.Host) + Copy(':' + IntToStr(L.Port), 1, 10 * Ord(L.Host <> '')),
       Fl, L.PollMin, Stt, St.Failures, NextU, Clean(St.LastResult),
       St.PendCount, St.PendBytes, Next]);
  end;

  Result := Result + 'END'#10;
end;

function TBinkMailer.Hello : String;
var
  I : Integer;
begin
  Result := 'HELLO ' + BINK_VERSION_STRING + #9'1'#10;

  EnterCriticalSection(FSessLock);
  try
    for I := 0 to FRing.Count - 1 do
      Result := Result + 'LOG ' + FRing[I] + #10;
  finally
    LeaveCriticalSection(FSessLock);
  end;

  Result := Result + BuildState;
end;

function TBinkMailer.HandleCommand(const Cmd : String) : String;
var
  Verb, Arg : String;
  P, I, N : Integer;
  A : TFTNAddress;
  L : TBinkLink;
  St : TLinkState;
  E : TSessEntry;
  Id : Integer;
begin
  P := Pos(' ', Cmd);

  if P = 0 then
  begin
    Verb := UpperCase(Cmd);
    Arg := '';
  end
  else
  begin
    Verb := UpperCase(Copy(Cmd, 1, P - 1));
    Arg := Trim(Copy(Cmd, P + 1, MaxInt));
  end;

  FDirty := True;
  Result := 'ERR unknown command ' + Verb;

  if Verb = 'PING' then
    Result := 'ACK pong'
  else if Verb = 'RESCAN' then
  begin
    FLastScan := 0;
    Result := 'ACK looking at the outbound';
  end
  else if Verb = 'RELOAD' then
  begin
    FReload := True;
    Result := 'ACK reading the settings again';
  end
  else if Verb = 'ABORT' then
  begin
    Id := StrToIntDef(Arg, -1);
    Result := 'ERR no such session';

    EnterCriticalSection(FSessLock);
    try
      for I := 0 to FSess.Count - 1 do
      begin
        E := TSessEntry(FSess[I]);

        if E.Id = Id then
        begin
          E.Sess.Cancel;
          Result := 'ACK session ' + IntToStr(Id) + ' is being ended';
          Break;
        end;
      end;
    finally
      LeaveCriticalSection(FSessLock);
    end;
  end
  else if (Verb = 'POLL') or (Verb = 'HOLD') or (Verb = 'FREE') then
  begin
    if (Verb = 'POLL') and (Arg = '*') then
    begin
      N := 0;

      for I := 0 to FSetup.LinkCount - 1 do
      begin
        L := FSetup.Links[I];
        St := State(L);

        if L.AnswerOnly or (L.Host = '') or St.Active then
          Continue;

        ProbeLink(St);

        if St.Waiting then
        begin
          St.Force := True;
          Inc(N);
        end;
      end;

      if N = 0 then
        Result := 'ERR no link has mail waiting'
      else
        Result := 'ACK ' + IntToStr(N) + ' link(s) will be called';

      Exit;
    end;

    if not TryParseAddress(Arg, A) then
      Exit('ERR "' + Arg + '" is not an address');

    L := FSetup.FindLink(A);

    if L = nil then
      Exit('ERR ' + FmtAddr(A) + ' is not a link');

    St := State(L);

    if Verb = 'HOLD' then
    begin
      St.Held := True;
      Result := 'ACK ' + St.Key + ' is held';
    end
    else if Verb = 'FREE' then
    begin
      St.Held := False;
      Result := 'ACK ' + St.Key + ' is released';
    end
    else if L.AnswerOnly then
      Result := 'ERR ' + St.Key + ' only answers calls'
    else if L.Host = '' then
      Result := 'ERR ' + St.Key + ' has no host to call'
    else if St.Active then
      Result := 'ERR ' + St.Key + ' is being called already'
    else
    begin
      St.Force := True;
      Result := 'ACK calling ' + St.Key;
    end;
  end;

  Log('Control: ' + Cmd + ' -> ' + Result);
end;

procedure TBinkMailer.ControlTick;
var
  Now_, Lines : String;
  T : QWord;
  Active : Boolean;
begin
  if FControl = nil then
    Exit;

  FControl.Tick;

  EnterCriticalSection(FSessLock);
  try
    Lines := FPendLog;
    FPendLog := '';
    Active := FSess.Count > 0;
  finally
    LeaveCriticalSection(FSessLock);
  end;

  if (Lines <> '') and (FControl.ClientCount > 0) then
    FControl.Broadcast(Lines);

  if FControl.ClientCount = 0 then
    Exit;

  T := GetTickCount64;

  if (FDirty and (T - FLastState >= 200)) or
     (Active and (T - FLastState >= 250)) or
     (T - FLastState >= 5000) then
  begin
    FDirty := False;
    FLastState := T;
    Now_ := BuildState;
    FControl.Broadcast(Now_);
  end;
end;

function TBinkMailer.Run : Integer;
var
  Tick : Integer;
  Err : String;
begin
  Result := 0;
  Tick := 0;

  if not LoadSetup(FFile, FSetup) then
    Exit(1);

  FStartKey := RestartKey(FSetup);
  CheckFileMode;
  Describe;

  FInbound := TBinkInbound.Create(FSetup.Inbound);
  FInboundUn := nil;

  if FSetup.InboundUnsecure <> '' then
    FInboundUn := TBinkInbound.Create(FSetup.InboundUnsecure);

  FBso := nil;
  FListener := nil;
  FListenThr := nil;
  FControl := nil;
  FStarted := UnixNow;
  try
    if FControlPath <> '' then
    begin
      FControl := TBinkControl.Create(FControlPath);
      FControl.OnCommand := @HandleCommand;
      FControl.OnHello := @Hello;

      if FControl.Start(Err) then
        Log('Control socket: ' + FControlPath)
      else
      begin
        Log('WARNING: no control socket: ' + Err);
        FreeAndNil(FControl);
      end;
    end;

    if FSetup.Bso <> '' then
      FBso := TBinkBso.Create(FSetup.Bso, FSetup.BsoZone)
    else
      Log('WARNING: no "bso" directory: nothing can be sent');

    if FSetup.Listen then
    begin
      FListener := TBinkListener.Create(FSetup.SessionConfig(nil),
        FInbound, FSetup.Port, FSetup.Bind);
      FListener.InboundUnsecure := FInboundUn;
      FListener.MaxSessions := FSetup.MaxSessions;
      FListener.OnLog := @EmitLog;
      FListener.OnSession := @NewSession;
      FListener.OnSessionDone := @InboundDone;
      FListenThr := TListenThread.Create(FListener);
      FListenThr.Start;
    end;

    Log('Mailer running');

    while not FStop do
    begin
      if FReload then
      begin
        FReload := False;
        DoReload;
      end;

      if (FListenThr <> nil) and FListenThr.Finished then
      begin
        Log('Fatal: the listener stopped: ' + FListenThr.Error);
        FFatal := True;
        Break;
      end;

      Inc(Tick);

      if Tick mod 5 = 0 then
      begin
        ReapPolls(False);
        Schedule;
      end;

      ControlTick;

      if not FStop then
        Sleep(200);
    end;

    Log('Mailer stopping');
  finally
    ReapPolls(True);

    if FListener <> nil then
      FListener.Stop;

    if FListenThr <> nil then
    begin
      FListenThr.WaitFor;
      FListenThr.Free;
    end;

    FListener.Free;
    FControl.Free;
    FBso.Free;
    FInbound.Free;
    FInboundUn.Free;
  end;

  if FFatal then
    Result := 1;
end;

end.
