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
  BinkSpool,
  BinkBso,
  {$IFDEF MKMSG}
  BinkAttach,
  {$ENDIF}
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
      ABso : TBinkSpool; ALog : TBinkLogEvent; AOnEnded : TSessionEnded);
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
    FBso       : TBinkSpool;
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
    procedure BatchEnded(Sender : TObject);
    procedure SessRemove(S : TBinkSession);
    function  FreqTmpDir : String;
    function  DeleteAllowed(const Tmp, Path : String) : Boolean;
    function  RunProgram(const Cmd : String; Args, Env : TStrings;
      Timeout : Integer; const Tag : String) : Integer;
    procedure RunHook(S : TBinkSession; const Cmd : String; Timeout : Integer);
    procedure DoFreq(S : TBinkSession; const ReqPath : String);
    procedure InboundDone(Sender : TObject; Session : TBinkSession);
    function  BuildState : String;
    function  Hello : String;
    function  HandleCommand(const Cmd : String) : String;
    function  HandleRequest(const Arg : String) : String;
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
  ABso : TBinkSpool; ALog : TBinkLogEvent; AOnEnded : TSessionEnded);
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
    [S.Domain, S.SysName, S.Sysop, S.Location, S.Inbound + '>' + S.InboundUnsecure, S.Bso + '>' + S.Netmail + '>' + S.AttachDir, S.Zone,
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
  if FSetup.Netmail <> '' then
    Log('Inbound: ' + FSetup.Inbound + '   attach style outbound: netmail ' +
      FSetup.Netmail + ', attach ' + FSetup.AttachDir +
      '   default zone ' + IntToStr(FSetup.BsoZone))
  else
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
  S.OnBatchEnd := @BatchEnded;
end;

{ The end of a batch in which files were exchanged (both sides offered
  OPT MB): the file requests received so far are answered now, so that the
  answer can go out in the next batch of this session. }
procedure TBinkMailer.BatchEnded(Sender : TObject);
var
  S : TBinkSession;
  I : Integer;
  Path : String;
  FreqOn : Boolean;
begin
  S := TBinkSession(Sender);

  EnterCriticalSection(FLock);
  try
    FreqOn := FSetup.Freq;
  finally
    LeaveCriticalSection(FLock);
  end;

  if not FreqOn then
    Exit;

  for I := S.Received.Count - 1 downto 0 do
    if LowerCase(ExtractFileExt(S.Received[I])) = '.req' then
    begin
      Path := S.Received[I];
      S.Received.Delete(I);
      DoFreq(S, Path);
    end;
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
  Cmd, Path : String;
  Tmo : Integer;
  FreqOn : Boolean;
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

  { file requests (a .req file received) are answered, not tossed }
  EnterCriticalSection(FLock);
  try
    FreqOn := FSetup.Freq;
  finally
    LeaveCriticalSection(FLock);
  end;

  if FreqOn then
    for I := S.Received.Count - 1 downto 0 do
      if LowerCase(ExtractFileExt(S.Received[I])) = '.req' then
      begin
        Path := S.Received[I];
        S.Received.Delete(I);
        DoFreq(S, Path);
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

{ Runs Cmd without a shell, with Args after the words of Cmd and Env added to
  the environment.  One at a time (a tosser does not want two of itself),
  killed after Timeout seconds; its output goes into the log, every line
  marked [Tag].  Returns the exit status, -1 when it could not be run, -2
  when it was killed. }
function TBinkMailer.RunProgram(const Cmd : String; Args, Env : TStrings;
  Timeout : Integer; const Tag : String) : Integer;
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
          Log('[' + Tag + '] ' + Clean(Rest));
          Rest := '';
        end;

        Break;
      end;

      L := Copy(Rest, 1, K - 1);
      Delete(Rest, 1, K);
      Log('[' + Tag + '] ' + Clean(L));
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
  Result := -1;
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

      for I := 0 to Args.Count - 1 do
        P.Parameters.Add(Args[I]);

      for I := 1 to GetEnvironmentVariableCount do
        P.Environment.Add(GetEnvironmentString(I));

      for I := 0 to Env.Count - 1 do
        P.Environment.Add(Env[I]);

      P.Options := [poUsePipes, poStderrToOutPut, poNoConsole];
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
      begin
        Log('[' + Tag + '] killed after ' + IntToStr(Timeout) + ' s');
        Result := -2;
      end
      else
      begin
        Result := P.ExitStatus;

        if Result <> 0 then
          Log('[' + Tag + '] exit status ' + IntToStr(Result))
        else
          Log('[' + Tag + '] done');
      end;
    except
      on E : Exception do
      begin
        Log('[' + Tag + '] cannot run ' + Cmd + ': ' + E.Message);
        Result := -1;
      end;
    end;
  finally
    P.Free;
    Parts.Free;
    LeaveCriticalSection(FHookLock);
  end;
end;

{ The command named by on-inbound, run without a shell with the paths of the
  files this session received as its arguments, and in its environment
    MKBINK_REMOTE   the remote's addresses
    MKBINK_SECURE   1 if the remote used a password, else 0
    MKBINK_ORIG     1 if we called, 0 if it called us
    MKBINK_FILES    the number of files }
procedure TBinkMailer.RunHook(S : TBinkSession; const Cmd : String;
  Timeout : Integer);
var
  Args, Env : TStringList;
  I : Integer;
begin
  Args := TStringList.Create;
  Env  := TStringList.Create;
  try
    for I := 0 to S.Received.Count - 1 do
      Args.Add(S.Received[I]);

    Env.Add('MKBINK_REMOTE=' + S.RemoteAddresses);
    Env.Add('MKBINK_SECURE=' + IntToStr(Ord(S.Secure)));
    Env.Add('MKBINK_ORIG=' + IntToStr(Ord(S.Originating)));
    Env.Add('MKBINK_FILES=' + IntToStr(S.Received.Count));
    Log(Format('Running %s (%d file(s) from %s)',
      [Trim(Copy(Cmd, 1, Pos(' ', Cmd + ' ') - 1)), S.Received.Count,
       S.RemoteAddresses]));
    RunProgram(Cmd, Args, Env, Timeout, 'hook');
  finally
    Env.Free;
    Args.Free;
  end;
end;

{ A file request (FTS-0006) the remote sent: the command named by on-freq is
  run with
      <requester> <secure|unsecure> <request file> <answer file>
  and in the environment MKBINK_REMOTE, MKBINK_SECURE, MKBINK_ORIG, as for
  on-inbound.  The request file is a copy of what arrived; the command writes
  the answer file, tab separated lines
      SEND<TAB>path            send this file (an absolute path), keep it
      SEND<TAB>path<TAB>^      send it and delete it after it was sent
      NOTE<TAB>text            for the log (and, later, for a netmail)
  Deleting: a "^" (or, from an SRIF processor, a "=" or "-" in front of the name) is only obeyed for a file directly in the freq-tmp
  directory (MKBINK_TMP: where a command puts what it makes for the request, such as a list of files).  For every other
  file the mark is ignored and the file is kept: a file request can never delete a real file.

  Instead of on-freq the setting on-freq-srif names a request processor that speaks SRIF (FSC-0086, FSP-1040): it is run with
  one argument, an SRIF file (Sysop, AKA, Baud, Time, RequestList, ResponseList, RemoteStatus PROTECTED / UNPROTECTED,
  SystemStatus LISTED / UNLISTED, SessionProtocoll, SessionType, Site, Location, Mailer, Version, OurAKA, TRANX).  Its response
  list has one file name per line, in front a "+" (keep), "=" (erase after it was sent) or "-" (erase after the session: taken as "="), or
  nothing (keep).  The limits and the hold mail are as below.  The SRIF file has no password of the session in it.

  The files are queued for the requester as hold mail (flavour H): when both
  sides offered OPT MB the request is answered at the end of the batch that
  brought it and the files go in the next batch of the same session (only to a
  requester that called us: hold mail is not sent to a system we called);
  otherwise they are sent when the requester calls us again to pick them up,
  and our mailer does not call it for them.  The limits of the
  settings (freq-max-files, freq-max-kb) are kept here as well as by the
  command.  Without a password (not secure) a request is only answered with
  freq-unsecure yes.  The request and the answer file are removed. }
function TBinkMailer.FreqTmpDir : String;
begin
  EnterCriticalSection(FLock);
  try
    Result := FSetup.FreqTmp;

    if Result = '' then
      Result := IncludeTrailingPathDelimiter(FSetup.Inbound) + 'freq-tmp';
  finally
    LeaveCriticalSection(FLock);
  end;

  Result := ExpandFileName(Result);
end;

{ A delete mark is only obeyed for a file that is directly in the freq-tmp directory and is no
  symbolic link: a request must not be able to delete a real file. }
function TBinkMailer.DeleteAllowed(const Tmp, Path : String) : Boolean;
var
  Base, P : String;
  St : Stat;
begin
  Result := False;

  if Tmp = '' then
    Exit;

  Base := IncludeTrailingPathDelimiter(ExpandFileName(Tmp));
  P := ExpandFileName(Path);

  if ExtractFilePath(P) <> Base then
    Exit;

  { lstat: a link is looked at itself, not at what it points to }
  if fpLStat(P, St) = 0 then
    Result := fpS_ISREG(St.st_mode);
end;

procedure TBinkMailer.DoFreq(S : TBinkSession; const ReqPath : String);
var
  Cmd, AnsPath, Who, Line, Kind, Path, Rest, Tmp, SrifPath, RspPath : String;
  Tmo, MaxFiles, I, P, Queued, Skipped : Integer;
  Srif : Boolean;
  Rsp : TStringList;
  Ch : Char;
  MaxKb, Bytes, Sz : Int64;
  Un : Boolean;
  Args, Env, Ans : TStringList;
  Remote : TFTNAddress;
  Act : TBinkOutAction;
  SR : TSearchRec;
begin
  EnterCriticalSection(FLock);
  try
    Cmd      := FSetup.OnFreq;
    Srif     := False;

    if FSetup.OnFreqSrif <> '' then
    begin
      Cmd := FSetup.OnFreqSrif;
      Srif := True;
    end;

    Tmo      := FSetup.HookTimeout;
    MaxFiles := FSetup.FreqMaxFiles;
    MaxKb    := FSetup.FreqMaxKb;
    Un       := FSetup.FreqUnsecure;
  finally
    LeaveCriticalSection(FLock);
  end;

  Who := S.RemoteAddresses;
  AnsPath := ReqPath + '.ans';
  SrifPath := ReqPath + '.srif';
  RspPath := ReqPath + '.rsp';
  Tmp := FreqTmpDir;
  ForceDirectories(Tmp);
  fpChmod(Tmp, &700);

  try
    if (not S.Secure) and (not Un) then
    begin
      Log('File request from ' + Who + ' ignored: the session had no ' +
        'password (freq-unsecure no)');
      Exit;
    end;

    if Cmd = '' then
    begin
      Log('File request from ' + Who + ' ignored: no on-freq command');
      Exit;
    end;

    if (S.RemoteCount = 0) or (FBso = nil) then
    begin
      Log('File request from ' + Who + ' ignored: no address or no outbound');
      Exit;
    end;

    Remote := S.RemoteAddr[0];
    Args := TStringList.Create;
    Env  := TStringList.Create;
    Ans  := TStringList.Create;
    try
      Env.Add('MKBINK_REMOTE=' + S.RemoteAddresses);
      Env.Add('MKBINK_SECURE=' + IntToStr(Ord(S.Secure)));
      Env.Add('MKBINK_ORIG=' + IntToStr(Ord(S.Originating)));
      Env.Add('MKBINK_TMP=' + Tmp);

      if Srif then
      begin
        { an SRIF request processor: the only argument is the SRIF file }
        Rsp := TStringList.Create;
        try
          Rsp.Add('Sysop ' + Clean(S.RemoteSysop));

          for I := 0 to S.RemoteCount - 1 do
            Rsp.Add('AKA ' + FmtAddr(S.RemoteAddr[I]));

          Rsp.Add('Baud 115200');
          Rsp.Add('Time -1');
          Rsp.Add('RequestList ' + ReqPath);
          Rsp.Add('ResponseList ' + RspPath);

          if S.Secure then
            Rsp.Add('RemoteStatus PROTECTED')
          else
            Rsp.Add('RemoteStatus UNPROTECTED');

          if FSetup.FindLink(Remote) <> nil then
            Rsp.Add('SystemStatus LISTED')
          else
            Rsp.Add('SystemStatus UNLISTED');

          Rsp.Add('SessionProtocoll BINKP');
          Rsp.Add('SessionType OTHER');

          if S.RemoteSysName <> '' then
            Rsp.Add('Site ' + Clean(S.RemoteSysName));

          if S.RemoteLocation <> '' then
            Rsp.Add('Location ' + Clean(S.RemoteLocation));

          Rsp.Add('Mailer mkbink');
          Rsp.Add('Version ' + Copy(BINK_VERSION_STRING,
            Pos('/', BINK_VERSION_STRING) + 1, 20));

          if Length(FSetup.Addresses) > 0 then
            Rsp.Add('OurAKA ' + FmtAddr(FSetup.Addresses[0]));

          Rsp.Add('TRANX ' + IntToHex(UnixNow - 315532800, 8));
          Rsp.SaveToFile(SrifPath);
          fpChmod(SrifPath, &600);
        finally
          Rsp.Free;
        end;

        Args.Add(SrifPath);
      end
      else
      begin
        Args.Add(Format('%d:%d/%d', [Remote.Zone, Remote.Net, Remote.Node]) +
          Copy('.' + IntToStr(Remote.Point), 1, 12 * Ord(Remote.Point <> 0)));

        if S.Secure then
          Args.Add('secure')
        else
          Args.Add('unsecure');

        Args.Add(ReqPath);
        Args.Add(AnsPath);
      end;

      Log('File request from ' + Who + ' (' + Copy('unsecure', 1 + 2 * Ord(S.Secure), 8 - 2 * Ord(S.Secure)) + Copy(', SRIF', 1, 6 * Ord(Srif)) + '): ' +
        Trim(Copy(Cmd, 1, Pos(' ', Cmd + ' ') - 1)));

      if RunProgram(Cmd, Args, Env, Tmo, 'freq') <> 0 then
      begin
        Log('File request from ' + Who + ': the command failed, nothing sent');
        Exit;
      end;

      if Srif then
      begin
        if not FileExists(RspPath) then
        begin
          Log('File request from ' + Who + ': the command wrote no response list');
          Exit;
        end;

        Queued := 0;
        Skipped := 0;
        Bytes := 0;
        Rsp := TStringList.Create;

        try
          try
            Rsp.LoadFromFile(RspPath);
          except
            on E : Exception do
            begin
              Log('File request from ' + Who + ': cannot read the response list: ' + E.Message);
              Rsp.Free;
              Exit;
            end;
          end;

          { the response list becomes answer lines: SEND <TAB> path [<TAB> ^] }
          for I := 0 to Rsp.Count - 1 do
          begin
            Line := Trim(Rsp[I]);

            if Line = '' then
              Continue;

            Ch := Line[1];

            if Ch in ['+', '=', '-'] then
              Line := Trim(Copy(Line, 2, MaxInt))
            else
              Ch := '+';

            if Ch = '+' then
              Ans.Add('SEND' + #9 + Line)
            else
              Ans.Add('SEND' + #9 + Line + #9 + '^');
          end;
        finally
          Rsp.Free;
        end;
      end
      else
      begin
        if not FileExists(AnsPath) then
        begin
          Log('File request from ' + Who + ': the command wrote no answer file');
          Exit;
        end;

        Queued := 0;
        Skipped := 0;
        Bytes := 0;

        try
          Ans.LoadFromFile(AnsPath);
        except
          on E : Exception do
          begin
            Log('File request from ' + Who + ': cannot read the answer: ' +
              E.Message);
            Exit;
          end;
        end;
      end;

      for I := 0 to Ans.Count - 1 do
      begin
        Line := TrimRight(Ans[I]);
        P := Pos(#9, Line);

        if P = 0 then
          Continue;

        Kind := UpperCase(Copy(Line, 1, P - 1));
        Rest := Copy(Line, P + 1, MaxInt);

        if Kind = 'NOTE' then
        begin
          Log('File request from ' + Who + ': ' + Clean(Rest));
          Continue;
        end;

        if Kind <> 'SEND' then
          Continue;

        Act := oaKeep;
        P := Pos(#9, Rest);

        if P > 0 then
        begin
          if Trim(Copy(Rest, P + 1, MaxInt)) = '^' then
            Act := oaDelete;

          Rest := Copy(Rest, 1, P - 1);
        end;

        Path := Rest;

        if (Act = oaDelete) and (not DeleteAllowed(Tmp, Path)) then
        begin
          Log('File request from ' + Who + ': ' + Clean(Path) +
            ' is not a plain file directly in ' + Tmp + ': the delete mark is ignored, the file is kept');
          Act := oaKeep;
        end;

        if (Path = '') or (Path[1] <> PathDelim) or
           (not FileExists(Path)) or DirectoryExists(Path) then
        begin
          Log('File request from ' + Who + ': not sent, not an existing ' +
            'file with an absolute path: ' + Clean(Path));
          Inc(Skipped);
          Continue;
        end;

        Sz := 0;

        if FindFirst(Path, faAnyFile, SR) = 0 then
        begin
          Sz := SR.Size;
          FindClose(SR);
        end;

        if (MaxFiles > 0) and (Queued >= MaxFiles) then
        begin
          Log('File request from ' + Who + ': ' + Path +
            ' not sent, over the limit of ' + IntToStr(MaxFiles) + ' files');
          Inc(Skipped);
          Continue;
        end;

        if (MaxKb > 0) and (Bytes + Sz > MaxKb * 1024) then
        begin
          Log('File request from ' + Who + ': ' + Path +
            ' not sent, over the limit of ' + IntToStr(MaxKb) + ' KB');
          Inc(Skipped);
          Continue;
        end;

        try
          FBso.Attach(Remote, Path, 'H', Act);
          Inc(Queued);
          Inc(Bytes, Sz);
        except
          on E : Exception do
          begin
            Log('File request from ' + Who + ': cannot queue ' + Path + ': ' +
              E.Message);
            Inc(Skipped);
          end;
        end;
      end;

      Log(Format('File request from %s: %d file(s) queued (%d bytes), ' +
        '%d not sent', [Who, Queued, Bytes, Skipped]));
    finally
      Ans.Free;
      Env.Free;
      Args.Free;
    end;
  finally
    DeleteFile(ReqPath);
    DeleteFile(AnsPath);
    DeleteFile(SrifPath);
    DeleteFile(RspPath);
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

{ REQ <addr> <host[:port]|-> <session password|-> <0|1> <request>[|<request>...]
  A request is "name [!password] [+time|-time]".  The requests are checked
  and written to the .req of the address; with 1 the system is called at
  once.  A host other than "-" is called as it is (no entry in the links
  file is needed: no password unless one is given, so an unsecure session);
  "-" uses the host of the link. }
function TBinkMailer.HandleRequest(const Arg : String) : String;
var
  Parts, Reqs, Toks : TStringList;
  A : TFTNAddress;
  L, Tmp : TBinkLink;
  St : TLinkState;
  I, J, P : Integer;
  Host, Pw, Line : String;
  Port : Word;
  DoPoll : Boolean;
  Names, Pws, Ups : TStringList;
  Nm, Up, Tok : String;

  function IsUp(const S : String) : Boolean;
  var
    K : Integer;
  begin
    Result := (Length(S) >= 2) and (S[1] in ['+', '-']);

    if Result then
      for K := 2 to Length(S) do
        if not (S[K] in ['0'..'9']) then
          Result := False;
  end;

begin
  Result := 'ERR usage: REQ addr host|- password|- 0|1 name [!pw] [+time]|...';

  if FBso = nil then
    Exit('ERR no outbound to put a request in');

  Parts := TStringList.Create;
  Reqs := TStringList.Create;
  Toks := TStringList.Create;
  Names := TStringList.Create;
  Pws := TStringList.Create;
  Ups := TStringList.Create;

  try
    { the first five words, then the rest }
    Line := Arg;

    for I := 1 to 4 do
    begin
      P := Pos(' ', Line);

      if P = 0 then
        Exit;

      Parts.Add(Copy(Line, 1, P - 1));
      Line := Trim(Copy(Line, P + 1, MaxInt));
    end;

    if Line = '' then
      Exit;

    if not TryParseAddress(Parts[0], A) then
      Exit('ERR "' + Parts[0] + '" is not an address');

    Host := Parts[1];
    Pw := Parts[2];
    DoPoll := Parts[3] = '1';
    Port := BINK_DEFAULT_PORT;

    if Host = '-' then
      Host := ''
    else
    begin
      P := Pos(':', Host);

      if P > 0 then
      begin
        Port := StrToIntDef(Copy(Host, P + 1, MaxInt), 0);
        Host := Copy(Host, 1, P - 1);

        if (Port = 0) or (Host = '') then
          Exit('ERR "' + Parts[1] + '" is not host:port');
      end;
    end;

    if Pw = '-' then
      Pw := '';

    L := FSetup.FindLink(A);

    if (Host = '') and DoPoll and ((L = nil) or (L.Host = '') or L.AnswerOnly) then
      Exit('ERR ' + FmtAddr(A) + ' has no host to call; give one');

    { split the requests: name, then !password, then +time/-time }
    Toks.Delimiter := '|';
    Toks.StrictDelimiter := True;
    Toks.DelimitedText := Line;

    for I := 0 to Toks.Count - 1 do
    begin
      Reqs.Clear;
      Reqs.Delimiter := ' ';
      Reqs.StrictDelimiter := True;
      Reqs.DelimitedText := Trim(Toks[I]);

      for J := Reqs.Count - 1 downto 0 do
        if Reqs[J] = '' then
          Reqs.Delete(J);

      if Reqs.Count = 0 then
        Continue;

      Nm := Reqs[0];
      Up := '';
      Line := '';

      if (Nm[1] = '!') or IsUp(Nm) then
        Exit('ERR a password or a time must follow the name it is for');

      for J := 1 to Reqs.Count - 1 do
      begin
        Tok := Reqs[J];

        if (Tok[1] = '!') and (Length(Tok) > 1) and (Line = '') then
          Line := Copy(Tok, 2, MaxInt)
        else if IsUp(Tok) and (Up = '') then
          Up := Tok
        else
          Exit('ERR "' + Tok + '" after ' + Nm + ' is not !password or +time/-time');
      end;

      Names.Add(Nm);
      Pws.Add(Line);
      Ups.Add(Up);
    end;

    if Names.Count = 0 then
      Exit;

    try
      for I := 0 to Names.Count - 1 do
        FBso.CheckRequest(Names[I], Pws[I], Ups[I]);

      for I := 0 to Names.Count - 1 do
        FBso.Request(A, Names[I], Pws[I], Ups[I]);
    except
      on E : Exception do
        Exit('ERR ' + E.Message);
    end;

    Result := 'ACK ' + IntToStr(Names.Count) + ' request(s) for ' + FmtAddr(A);

    if not DoPoll then
    begin
      Result := Result + ' queued';
      Log('Control: file request queued for ' + FmtAddr(A));
      Exit;
    end;

    if ActivePolls >= FSetup.MaxPolls then
      Exit(Result + ' queued; too many calls going on, not called');

    if L <> nil then
      St := State(L)
    else
    begin
      Tmp := TBinkLink.Create;
      Tmp.Address := A;
      St := State(Tmp);
      Tmp.Free;
    end;

    if St.Active then
      Exit(Result + ' queued; ' + St.Key + ' is being called already');

    if (Host = '') then
    begin
      St.Force := True;
      Result := Result + ' queued; calling ' + St.Key;
    end
    else
    begin
      Tmp := TBinkLink.Create;

      try
        Tmp.Address := A;
        Tmp.Name := 'request';
        Tmp.Host := Host;
        Tmp.Port := Port;
        Tmp.Password := Pw;

        if L <> nil then
        begin
          Tmp.HaveUs := L.HaveUs;
          Tmp.Us := L.Us;
          Tmp.Plz := L.Plz;
          Tmp.Nr := L.Nr;

          if (Pw = '') and (L.Host = Host) then
            Tmp.Password := L.Password;
        end;

        StartPoll(Tmp, St, 'file request');
      finally
        Tmp.Free;
      end;

      Result := Result + ' queued; calling ' + St.Key + ' at ' + Host + ':' + IntToStr(Port);
    end;
  finally
    Parts.Free;
    Reqs.Free;
    Toks.Free;
    Names.Free;
    Pws.Free;
    Ups.Free;
  end;
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
  else if Verb = 'REQ' then
    Result := HandleRequest(Arg)
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

    if FSetup.Netmail <> '' then
    begin
      {$IFDEF MKMSG}
      FBso := TBinkAttachSpool.Create(FSetup.Netmail, FSetup.AttachDir,
        FSetup.BsoZone, FSetup.Addresses[0]);
      {$ELSE}
      Log('ERROR: this build has no attach style support (it needs the ' +
        'MKMsg units): nothing can be sent');
      {$ENDIF}
    end
    else if FSetup.Bso <> '' then
      begin
        FBso := TBinkBso.Create(FSetup.Bso, FSetup.BsoZone);

        if Length(FSetup.Addresses) > 0 then
          TBinkBso(FBso).SetOwn(FSetup.Addresses[0]);
      end
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
