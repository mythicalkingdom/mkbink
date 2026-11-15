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
  BinkBso;

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
    LastResult  : String;
  end;

  TPollThread = class(TThread)
  private
    FSession : TBinkSession;
    FInbound : TBinkInbound;
    FNode    : TBinkNodeInfo;
    FState   : TLinkState;
    FOk      : Boolean;
    FError   : String;
  protected
    procedure Execute; override;
  public
    constructor Create(AState : TLinkState; const ACfg : TBinkConfig;
      const ANode : TBinkNodeInfo; const AInboundPath : String;
      ABso : TBinkBso; ALog : TBinkLogEvent);
    destructor Destroy; override;
    procedure Cancel;
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
    FListener  : TBinkListener;
    FListenThr : TListenThread;
    FStates    : TStringList;       { Key -> TLinkState }
    FPolls     : TFPList;           { TPollThread }
    FLastScan  : Int64;
    FFatal     : Boolean;
    FStartKey  : String;

    procedure Log(const Msg : String);
    function  State(Link : TBinkLink) : TLinkState;
    function  LoadSetup(const Path : String; out S : TBinkSetup) : Boolean;
    function  RestartKey(S : TBinkSetup) : String;
    procedure DoReload;
    procedure Describe;
    procedure CheckFileMode;
    procedure Schedule;
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

    { Runs until Stop.  Result: 0 = stopped, 1 = could not start / fatal. }
    function Run : Integer;

    procedure Stop;
    procedure RequestReload;
  end;

function NowSec : Int64;

{ Seconds to wait after Failures failed calls in a row (1 = the first). }
function BackoffSeconds(Failures, RetryMin, RetryMax : Integer) : Integer;


implementation

uses
  {$IFDEF UNIX}
  BaseUnix,
  {$ENDIF}
  BinkOutbound;

function NowSec : Int64;
begin
  Result := GetTickCount64 div 1000;
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
  const ANode : TBinkNodeInfo; const AInboundPath : String;
  ABso : TBinkBso; ALog : TBinkLogEvent);
begin
  inherited Create(True);
  FreeOnTerminate := False;
  FState := AState;
  FNode := ANode;
  FInbound := TBinkInbound.Create(AInboundPath);
  FSession := TBinkSession.Create(ACfg);
  FSession.Inbound := FInbound;
  FSession.Bso := ABso;
  FSession.OnLog := ALog;
  FSession.LogPrefix := '[poll ' + AddressToString(ANode.Address) + '] ';
end;

destructor TPollThread.Destroy;
begin
  FSession.Free;
  FInbound.Free;
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
end;

destructor TBinkMailer.Destroy;
begin
  FPolls.Free;
  FStates.Free;
  FSetup.Free;
  DoneCriticalSection(FLock);
  inherited Destroy;
end;

procedure TBinkMailer.Log(const Msg : String);
begin
  if Assigned(FLog) then
    FLog(Msg);
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
  K := AddressToString(Link.Address);
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
    Result := Result + AddressToString(S.Addresses[I]) + ' ';

  Result := Result + Format('|%s|%s|%s|%s|%s|%s|%d|%s|%d|%s|%d|%d|%d|%s|%s',
    [S.Domain, S.SysName, S.Sysop, S.Location, S.Inbound, S.Bso, S.Zone,
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
    S := S + ' ' + AddressToString(FSetup.Addresses[I]);

  Log('Our address(es):' + S);
  Log('Inbound: ' + FSetup.Inbound + '   BSO outbound: ' +
    FSetup.Bso + '   default zone ' + IntToStr(FSetup.BsoZone));

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

    Log(Format('Link %s %s: %s', [AddressToString(L.Address), L.Name, S]));
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
    [AddressToString(Link.Address), Link.Name, Link.Host, Link.Port, Why]));

  T := TPollThread.Create(St, Cfg, Node, FSetup.Inbound, FBso,
    FLog);
  St.Active := True;
  FPolls.Add(T);
  T.Start;
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
      try
        St.Waiting := (FBso <> nil) and (FBso.Pending(L.Address, False) > 0);
      except
        on E : Exception do
        begin
          St.Waiting := False;
          Log('Outbound error for ' + St.Key + ': ' + E.Message);
        end;
      end;

    if Now_ < St.NextAttempt then
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

  if T.Ok then
  begin
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
    Inc(St.Failures);
    Wait := BackoffSeconds(St.Failures, FSetup.RetryMin, FSetup.RetryMax);
    St.NextAttempt := NowSec + Wait;
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

function TBinkMailer.Run : Integer;
var
  I : Integer;
begin
  Result := 0;

  if not LoadSetup(FFile, FSetup) then
    Exit(1);

  FStartKey := RestartKey(FSetup);
  CheckFileMode;
  Describe;

  FInbound := TBinkInbound.Create(FSetup.Inbound);
  FBso := nil;
  FListener := nil;
  FListenThr := nil;
  try
    if FSetup.Bso <> '' then
      FBso := TBinkBso.Create(FSetup.Bso, FSetup.BsoZone)
    else
      Log('WARNING: no "bso" directory: nothing can be sent');

    if FSetup.Listen then
    begin
      FListener := TBinkListener.Create(FSetup.SessionConfig(nil),
        FInbound, FSetup.Port, FSetup.Bind);
      FListener.MaxSessions := FSetup.MaxSessions;
      FListener.OnLog := FLog;
      FListener.OnSession := @NewSession;
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

      ReapPolls(False);
      Schedule;

      for I := 1 to 5 do
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
    FBso.Free;
    FInbound.Free;
  end;

  if FFatal then
    Result := 1;
end;

end.
