program MkBink;

{$mode objfpc}{$H+}

{ binkp mailer front end.

    mkbink poll   host[:port] -a ADDR [-r REMOTE] [options]
    mkbink listen             -a ADDR [options]
    mkbink queue  -O DIR -t ADDR file...

  See "mkbink help". }

uses
  {$IFDEF UNIX}
  cthreads,
  BaseUnix,
  {$ENDIF}
  Classes,
  SysUtils,
  BinkTypes,
  BinkNode,
  BinkInbound,
  BinkOutbound,
  BinkBso,
  BinkSession,
  BinkListener;

type
  TOptions = record
    Mode      : String;
    Target    : String;      { poll: host[:port] }
    Config    : TBinkConfig;
    Remote    : String;      { poll: expected address; listen: ';' list }
    Password  : String;
    Port      : Word;
    BindAddr  : String;
    InDir     : String;
    OutDir    : String;      { flat outbound directory }
    OutDirSet : Boolean;
    BsoDir    : String;      { BSO outbound base directory }
    DefZone   : Integer;     { BSO default zone, -1 = not given }
    HaveAddr  : Boolean;
    KillSent  : Boolean;
    MaxSess   : Integer;
    { queue }
    QTarget   : String;
    Flavour   : Char;
    QDelete   : Boolean;
    QFiles    : TStringList;
  end;

  POptions = ^TOptions;

  { Glue for listen mode: lets only the configured links in and picks
    the outbound for each caller. }
  TServerHooks = class
  public
    Opts    : POptions;
    Bso     : TBinkBso;
    Allowed : array of TFTNAddress;

    function  Auth(const Remote : TFTNAddress;
                out Password : String) : Boolean;
    procedure Authenticated(Sender : TObject);
    procedure NewSession(Sender : TObject; Session : TBinkSession);
  end;

  { Log output shared by all session threads. }
  TLog = class
  private
    FLock : TRTLCriticalSection;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Print(const Msg : String);
  end;

var
  GListener : TBinkListener;

constructor TLog.Create;
begin
  inherited Create;
  InitCriticalSection(FLock);
end;

destructor TLog.Destroy;
begin
  DoneCriticalSection(FLock);
  inherited Destroy;
end;

procedure TLog.Print(const Msg : String);
begin
  EnterCriticalSection(FLock);
  try
    Writeln(FormatDateTime('yyyy-mm-dd hh:nn:ss', Now), '  ', Msg);
    Flush(Output);
  finally
    LeaveCriticalSection(FLock);
  end;
end;

procedure Usage;
begin
  Writeln('mkbink - binkp mailer (FTS-1026, 1027, 1028, 1029)');
  Writeln;
  Writeln('Usage:');
  Writeln('  mkbink poll <host[:port]> -a <our addr> [-r <remote addr>] [options]');
  Writeln('  mkbink listen -a <our addr> [options]');
  Writeln('  mkbink queue -O <bso dir> -t <addr> [-F flavour] [-x] <file>...');
  Writeln;
  Writeln('Options:');
  Writeln('  -a ADDR   our FTN address, e.g. 1:123/456 (required for poll/listen)');
  Writeln('  -r ADDR   poll: address we expect to reach.');
  Writeln('            listen: address allowed to call (repeatable;');
  Writeln('            none given = accept any address)');
  Writeln('  -P PASS   session password (or env BINK_PASSWORD).');
  Writeln('            poll: sent to the remote; listen: required from callers');
  Writeln('  -p PORT   listen port (default ', BINK_DEFAULT_PORT, ')');
  Writeln('  -b ADDR   listen: bind to this local IPv4 address');
  Writeln('  -m N      listen: serve up to N callers at once (default ',
    BINK_DEFAULT_MAX_SESSIONS, ');');
  Writeln('            further callers are told M_BSY');
  Writeln('  -i DIR    inbound directory (default ./inbound)');
  Writeln;
  Writeln('Outbound (use -O for a BSO spool shared with a tosser / binkd,');
  Writeln('          and/or -o for plain directories):');
  Writeln('  -O DIR    BSO outbound base directory.  Mail queued there for the');
  Writeln('            remote system is sent; hold flavour only when it calls us');
  Writeln('  -Z ZONE   the BSO default zone (default: the zone of -a)');
  Writeln('  -o DIR    plain outbound directory (default ./outbound if no -O)');
  Writeln('              poll:   files directly in DIR are sent');
  Writeln('              listen: files in DIR/<zone>.<net>.<node>.<point>/');
  Writeln('                      are sent to that system when it calls');
  Writeln('  -k        plain directories: delete sent files instead of');
  Writeln('            moving them to a "sent" sub directory');
  Writeln;
  Writeln('queue:');
  Writeln('  -t ADDR   system to send the file(s) to');
  Writeln('  -F FLAV   flavour: I(mmediate) C(rash) D(irect) N(ormal, default) H(old)');
  Writeln('  -x        delete the file after it was sent (default: keep it)');
  Writeln;
  Writeln('Session:');
  Writeln('  -d DOMAIN network domain appended to our address, e.g. fidonet');
  Writeln('  -n NAME   system name        -s NAME   sysop name');
  Writeln('  -l TEXT   location');
  Writeln('  -t SECS   inactivity timeout (default ', BINK_DEFAULT_TIMEOUT, ')');
  Writeln('  -c        listen: refuse cleartext passwords (require CRAM)');
  Writeln('  -z        offer PLZ dataframe compression (FTS-1029)');
  Writeln('  -N        ask the remote for non-reliable (NR) mode (FTS-1028);');
  Writeln('            only for links that keep dropping: it is slower');
  Writeln;
  Writeln('Exit status of poll: 0 = session completed, 1 = failed.');
end;

function NeedArg(Idx : Integer; const Opt : String) : String;
begin
  if Idx > ParamCount then
  begin
    Writeln(StdErr, 'Option ', Opt, ' needs an argument');
    Halt(2);
  end;

  Result := ParamStr(Idx);
end;

procedure Die(const Msg : String);
begin
  Writeln(StdErr, Msg);
  Halt(2);
end;

procedure ParseOptions(var O : TOptions);
var
  I : Integer;
  A : String;
  Allowed : TStringList;
begin
  O.Config := DefaultBinkConfig;
  O.Port   := BINK_DEFAULT_PORT;
  O.InDir  := 'inbound';
  O.OutDir := 'outbound';
  O.OutDirSet := False;
  O.BsoDir := '';
  O.DefZone := -1;
  O.HaveAddr := False;
  O.Password := GetEnvironmentVariable('BINK_PASSWORD');
  O.Mode := '';
  O.Target := '';
  O.Remote := '';
  O.BindAddr := '';
  O.KillSent := False;
  O.MaxSess := BINK_DEFAULT_MAX_SESSIONS;
  O.QTarget := '';
  O.Flavour := 'N';
  O.QDelete := False;
  O.QFiles := TStringList.Create;

  if ParamCount < 1 then
  begin
    Usage;
    Halt(2);
  end;

  O.Mode := LowerCase(ParamStr(1));

  if (O.Mode = 'help') or (O.Mode = '-h') or (O.Mode = '--help') then
  begin
    Usage;
    Halt(0);
  end;

  if (O.Mode <> 'poll') and (O.Mode <> 'listen') and
     (O.Mode <> 'queue') then
  begin
    Writeln(StdErr, 'Unknown command "', O.Mode, '"');
    Usage;
    Halt(2);
  end;

  Allowed := TStringList.Create;

  I := 2;

  while I <= ParamCount do
  begin
    A := ParamStr(I);

    if A = '-a' then
    begin
      Inc(I);
      O.Config.Address := ParseAddress(NeedArg(I, A));
      O.HaveAddr := True;
    end
    else if A = '-r' then
    begin
      Inc(I);
      Allowed.Add(NeedArg(I, A));
    end
    else if A = '-P' then
    begin
      Inc(I);
      O.Password := NeedArg(I, A);
    end
    else if A = '-p' then
    begin
      Inc(I);
      O.Port := StrToInt(NeedArg(I, A));
    end
    else if A = '-b' then
    begin
      Inc(I);
      O.BindAddr := NeedArg(I, A);
    end
    else if A = '-m' then
    begin
      Inc(I);
      O.MaxSess := StrToInt(NeedArg(I, A));

      if O.MaxSess < 1 then
        Die('-m must be at least 1');
    end
    else if A = '-i' then
    begin
      Inc(I);
      O.InDir := NeedArg(I, A);
    end
    else if A = '-o' then
    begin
      Inc(I);
      O.OutDir := NeedArg(I, A);
      O.OutDirSet := True;
    end
    else if A = '-O' then
    begin
      Inc(I);
      O.BsoDir := NeedArg(I, A);
    end
    else if A = '-Z' then
    begin
      Inc(I);
      O.DefZone := StrToInt(NeedArg(I, A));
    end
    else if A = '-d' then
    begin
      Inc(I);
      O.Config.Domain := NeedArg(I, A);
    end
    else if A = '-n' then
    begin
      Inc(I);
      O.Config.SysName := NeedArg(I, A);
    end
    else if A = '-s' then
    begin
      Inc(I);
      O.Config.Sysop := NeedArg(I, A);
    end
    else if A = '-l' then
    begin
      Inc(I);
      O.Config.Location := NeedArg(I, A);
    end
    else if A = '-t' then
    begin
      Inc(I);

      if O.Mode = 'queue' then
        O.QTarget := NeedArg(I, A)
      else
        O.Config.Timeout := StrToInt(NeedArg(I, A));
    end
    else if A = '-F' then
    begin
      Inc(I);
      A := UpperCase(NeedArg(I, '-F'));

      if (Length(A) <> 1) or (Pos(A, 'ICDNH') = 0) then
        Die('Flavour must be one of I, C, D, N, H');

      O.Flavour := A[1];
    end
    else if A = '-x' then
      O.QDelete := True
    else if A = '-k' then
      O.KillSent := True
    else if A = '-c' then
      O.Config.RequireCram := True
    else if A = '-N' then
      O.Config.NonReliable := True
    else if A = '-z' then
      O.Config.Compress := True
    else if (A <> '') and (A[1] <> '-') and (O.Mode = 'poll') and
            (O.Target = '') then
      O.Target := A
    else if (A <> '') and (A[1] <> '-') and (O.Mode = 'queue') then
      O.QFiles.Add(A)
    else
      Die('Unknown option "' + A + '"');

    Inc(I);
  end;

  O.Config.Password := O.Password;

  if O.Mode = 'queue' then
  begin
    if O.BsoDir = '' then
      Die('queue needs -O <bso outbound directory>');
    if O.QTarget = '' then
      Die('queue needs -t <address>');
    if O.QFiles.Count = 0 then
      Die('queue needs at least one file');
  end
  else
  begin
    if not O.HaveAddr then
      Die('Our address (-a) is required');
  end;

  if O.Mode = 'poll' then
  begin
    if O.Target = '' then
      Die('poll needs host[:port]');

    if Allowed.Count > 0 then
      O.Remote := Allowed[0];
  end
  else if O.Mode = 'listen' then
  begin
    { remember allowed links in Remote, ';' separated }
    for I := 0 to Allowed.Count - 1 do
    begin
      if O.Remote <> '' then
        O.Remote := O.Remote + ';';

      O.Remote := O.Remote + Allowed[I];
    end;
  end;

  Allowed.Free;
end;

{ BSO default zone: -Z, else the zone of our own address. }
function MakeBso(const O : TOptions;
  const Fallback : TFTNAddress) : TBinkBso;
var
  Z : Integer;
begin
  Z := O.DefZone;

  if Z < 0 then
  begin
    if O.HaveAddr then
      Z := O.Config.Address.Zone
    else
      Z := Fallback.Zone;
  end;

  Result := TBinkBso.Create(O.BsoDir, Z);
end;

{ Plain directories are used when asked for with -o, or when there is
  no BSO spool. }
function UseFlat(const O : TOptions) : Boolean;
begin
  Result := O.OutDirSet or (O.BsoDir = '');
end;

{ ---------------------------------------------------------------- }

function TServerHooks.Auth(
  const Remote : TFTNAddress;
  out Password : String) : Boolean;
var
  I : Integer;
begin
  Password := Opts^.Password;

  if Length(Allowed) = 0 then
    Exit(True);

  Result := False;

  for I := 0 to High(Allowed) do
    if SameAddress(Allowed[I], Remote) then
      Exit(True);
end;

procedure TServerHooks.Authenticated(Sender : TObject);
var
  S    : TBinkSession;
  Outb : TBinkOutbound;
  I    : Integer;
begin
  S := Sender as TBinkSession;

  if not UseFlat(Opts^) then
    Exit;

  { plain per-link directories: outbound/<zone>.<net>.<node>.<point>/ }
  Outb := TBinkOutbound.Create;
  Outb.KillSent := Opts^.KillSent;

  for I := 0 to S.RemoteCount - 1 do
    Outb.AddDir(
      IncludeTrailingPathDelimiter(Opts^.OutDir) +
      AddressToDirName(S.RemoteAddr[I]));

  S.Outbound := Outb;
  S.OwnsOutbound := True;
end;

procedure TServerHooks.NewSession(
  Sender : TObject;
  Session : TBinkSession);
begin
  Session.OnAuth := @Auth;
  Session.OnAuthenticated := @Authenticated;

  if Bso <> nil then
    Session.Bso := Bso;
end;

{ ---------------------------------------------------------------- }

{$IFDEF UNIX}
procedure HandleSignal(Sig : cint); cdecl;
begin
  if GListener <> nil then
    GListener.Stop;
end;
{$ENDIF}

function DoPoll(var O : TOptions) : Integer;
var
  Node : TBinkNodeInfo;
  P    : Integer;
  Sess : TBinkSession;
  Outb : TBinkOutbound;
  Inb  : TBinkInbound;
  Lg   : TLog;
  Bso  : TBinkBso;
begin
  Node := Default(TBinkNodeInfo);

  P := LastDelimiter(':', O.Target);

  if P > 0 then
  begin
    Node.Host := Copy(O.Target, 1, P - 1);
    Node.Port := StrToInt(Copy(O.Target, P + 1, 10));
  end
  else
  begin
    Node.Host := O.Target;
    Node.Port := BINK_DEFAULT_PORT;
  end;

  if O.Remote <> '' then
    Node.Address := ParseAddress(O.Remote);

  Node.Password := O.Password;

  Lg   := TLog.Create;
  Outb := TBinkOutbound.Create;
  Inb  := TBinkInbound.Create(O.InDir);
  Sess := TBinkSession.Create(O.Config);
  Bso  := nil;
  try
    Outb.KillSent := O.KillSent;

    if UseFlat(O) then
      Outb.Scan(O.OutDir);

    if O.BsoDir <> '' then
    begin
      Bso := MakeBso(O, Node.Address);
      Sess.Bso := Bso;
    end;

    Sess.Inbound  := Inb;
    Sess.Outbound := Outb;
    Sess.OnLog    := @Lg.Print;

    if Sess.Originate(Node) then
      Result := 0
    else
      Result := 1;
  finally
    Sess.Free;
    Bso.Free;
    Inb.Free;
    Outb.Free;
    Lg.Free;
  end;
end;

function DoListen(var O : TOptions) : Integer;
var
  Hooks : TServerHooks;
  Inb   : TBinkInbound;
  Lg    : TLog;
  Parts : TStringList;
  I     : Integer;
  Dummy : TFTNAddress;
begin
  Lg    := TLog.Create;
  Inb   := TBinkInbound.Create(O.InDir);
  Hooks := TServerHooks.Create;
  Parts := TStringList.Create;
  try
    Hooks.Opts := @O;

    if O.BsoDir <> '' then
    begin
      Dummy := Default(TFTNAddress);
      Hooks.Bso := MakeBso(O, Dummy);
    end;

    Parts.Delimiter := ';';
    Parts.StrictDelimiter := True;
    Parts.DelimitedText := O.Remote;

    for I := 0 to Parts.Count - 1 do
    begin
      if Parts[I] = '' then
        Continue;

      SetLength(Hooks.Allowed, Length(Hooks.Allowed) + 1);
      Hooks.Allowed[High(Hooks.Allowed)] := ParseAddress(Parts[I]);
    end;

    if O.Password = '' then
      Lg.Print('WARNING: no password set; callers are not authenticated');

    GListener := TBinkListener.Create(
      O.Config, Inb, O.Port, O.BindAddr);
    try
      GListener.MaxSessions := O.MaxSess;
      GListener.OnLog := @Lg.Print;
      GListener.OnSession := @Hooks.NewSession;

      {$IFDEF UNIX}
      fpSignal(SIGINT,  @HandleSignal);
      fpSignal(SIGTERM, @HandleSignal);
      {$ENDIF}

      try
        GListener.Run;
        Result := 0;
      except
        on E : Exception do
        begin
          Lg.Print('Fatal: ' + E.Message);
          Result := 1;
        end;
      end;
    finally
      FreeAndNil(GListener);
    end;
  finally
    Parts.Free;
    Hooks.Bso.Free;
    Hooks.Free;
    Inb.Free;
    Lg.Free;
  end;
end;

function DoQueue(var O : TOptions) : Integer;
var
  Target : TFTNAddress;
  Bso    : TBinkBso;
  I      : Integer;
  Flow   : String;
  Act    : TBinkOutAction;
begin
  Target := ParseAddress(O.QTarget);
  Bso := MakeBso(O, Target);
  try
    if O.QDelete then
      Act := oaDelete
    else
      Act := oaKeep;

    for I := 0 to O.QFiles.Count - 1 do
    begin
      Flow := Bso.Attach(Target, O.QFiles[I], O.Flavour, Act);

      Writeln(Format('Queued %s for %s -> %s',
        [ExpandFileName(O.QFiles[I]), AddressToString(Target), Flow]));
    end;

    Result := 0;
  finally
    Bso.Free;
  end;
end;

var
  Opts : TOptions;

begin
  try
    ParseOptions(Opts);

    if Opts.Mode = 'poll' then
      Halt(DoPoll(Opts))
    else if Opts.Mode = 'queue' then
      Halt(DoQueue(Opts))
    else
      Halt(DoListen(Opts));
  except
    on E : Exception do
    begin
      Writeln(StdErr, 'Error: ', E.Message);
      Halt(1);
    end;
  end;
end.
