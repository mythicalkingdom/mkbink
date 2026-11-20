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
  BinkSpool,
  BinkBso,
  {$IFDEF MKMSG}
  BinkAttach,
  {$ENDIF}
  BinkSession,
  BinkListener,
  BinkLinks,
  BinkMailer;

type
  TOptions = record
    Mode      : String;
    LinksFile : String;      { run / check: the settings file }
    ControlSock : String;    { run: Unix socket for a monitor }
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
    MsgDir    : String;      { attach style: netmail *.msg directory }
    AttachDir : String;      { attach style: attached files, packets }
    DefZone   : Integer;     { BSO default zone, -1 = not given }
    HaveAddr  : Boolean;
    KillSent  : Boolean;
    MaxSess   : Integer;
    { queue }
    QTarget   : String;
    Flavour   : Char;
    QDelete   : Boolean;
    QTruncate : Boolean;
    QRequest  : Boolean;     { queue -R: the arguments are file requests }
    QFiles    : TStringList;
  end;

  POptions = ^TOptions;

  { Glue for listen mode: lets only the configured links in and picks
    the outbound for each caller. }
  TServerHooks = class
  public
    Opts    : POptions;
    Bso     : TBinkSpool;
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
  GMailer   : TBinkMailer;

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
  Writeln('  mkbink queue -O <bso dir> -t <addr> [-F flavour] [-x | -T] <file>...');
  Writeln('  mkbink queue -O <bso dir> -t <addr> -R <name> [!password] ...   ask the system for files');
  Writeln('  mkbink run -f <settings file> [-S <socket>]');
  Writeln('                                     answer calls and call the links in the file;');
  Writeln('                                     -S: a Unix socket a monitor can connect to (see src/lib/binkcontrol.pas)');
  Writeln('  mkbink check -f <settings file>    check the settings file and show what it says');
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
  Writeln('  -M DIR    attach (FrontDoor) style instead of -O: the directory of');
  Writeln('            netmail *.msg files.  Needs -A.  Messages for the remote are');
  Writeln('            sent (crash first); File Attach messages send their file');
  Writeln('  -A DIR    attach style: where attached files and the packets built');
  Writeln('            from netmail live.  (-Z is the zone for messages without one;');
  Writeln('            queue needs -a.  Built only when the MKMsg units were found)');
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
  Writeln('  -T        truncate the file to 0 bytes after it was sent (BSO flow line #file)');
  Writeln('  -R        the arguments are file requests (FTS-0006): a name, and !password (6 characters');
  Writeln('            at most) after the name it is for; they are added to the .req of the system');
  Writeln;
  Writeln('Session:');
  Writeln('  -d DOMAIN network domain appended to our address, e.g. fidonet');
  Writeln('  -n NAME   system name        -s NAME   sysop name');
  Writeln('  -l TEXT   location');
  Writeln('  -t SECS   inactivity timeout (default ', BINK_DEFAULT_TIMEOUT, ')');
  Writeln('  -c        listen: refuse cleartext passwords (require CRAM)');
  Writeln('  -z        offer PLZ dataframe compression (FTS-1029)');
  Writeln('  -E        never use CRYPT (default: used when the remote offers it)');
  Writeln('  -N        ask the remote for non-reliable (NR) mode (FTS-1028);');
  Writeln('            only for links that keep dropping: it is slower');
  Writeln;
  Writeln('Exit status of poll: 0 = session completed, 1 = failed.');
  Writeln;
  Writeln('run keeps going until SIGINT / SIGTERM; SIGHUP reads the settings file');
  Writeln('again (links, passwords and intervals; addresses, paths and port need a');
  Writeln('restart).  The file format is described at the top of src/lib/binklinks.pas.');
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
  O.MsgDir := '';
  O.AttachDir := '';
  O.DefZone := -1;
  O.HaveAddr := False;
  O.Password := GetEnvironmentVariable('BINK_PASSWORD');
  O.Mode := '';
  O.LinksFile := '';
  O.ControlSock := '';
  O.Target := '';
  O.Remote := '';
  O.BindAddr := '';
  O.KillSent := False;
  O.MaxSess := BINK_DEFAULT_MAX_SESSIONS;
  O.QTarget := '';
  O.Flavour := 'N';
  O.QDelete := False;
  O.QTruncate := False;
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
     (O.Mode <> 'queue') and (O.Mode <> 'run') and (O.Mode <> 'check') then
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
    else if A = '-f' then
    begin
      Inc(I);
      O.LinksFile := NeedArg(I, A);
    end
    else if A = '-S' then
    begin
      Inc(I);
      O.ControlSock := NeedArg(I, A);
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
    else if A = '-M' then
    begin
      Inc(I);
      O.MsgDir := NeedArg(I, A);
    end
    else if A = '-A' then
    begin
      Inc(I);
      O.AttachDir := NeedArg(I, A);
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
    else if A = '-T' then
      O.QTruncate := True
    else if (A = '-R') and (O.Mode = 'queue') then
      O.QRequest := True
    else if A = '-k' then
      O.KillSent := True
    else if A = '-c' then
      O.Config.RequireCram := True
    else if A = '-N' then
      O.Config.NonReliable := True
    else if A = '-z' then
      O.Config.Compress := True
    else if A = '-E' then
      O.Config.NoCrypt := True
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

  if (O.Mode = 'run') or (O.Mode = 'check') then
  begin
    if O.LinksFile = '' then
      Die(O.Mode + ' needs -f <settings file>');

    Allowed.Free;
    Exit;
  end;

  if (O.MsgDir <> '') or (O.AttachDir <> '') then
  begin
    {$IFNDEF MKMSG}
    Die('This build has no attach style support (it needs the MKMsg ' +
        'units: see the Makefile, variable MKMSG)');
    {$ENDIF}
    if (O.MsgDir = '') or (O.AttachDir = '') then
      Die('Attach style needs both -M <netmail directory> and ' +
          '-A <attach directory>');
    if O.BsoDir <> '' then
      Die('Use either -O (BSO) or -M/-A (attach style), not both');
  end;

  if O.Mode = 'queue' then
  begin
    if (O.BsoDir = '') and (O.MsgDir = '') then
      Die('queue needs -O <bso outbound directory> or -M/-A');
    if (O.MsgDir <> '') and (not O.HaveAddr) then
      Die('queue in attach style needs our address (-a)');
    if O.QTarget = '' then
      Die('queue needs -t <address>');
    if O.QFiles.Count = 0 then
      if O.QRequest then
        Die('queue -R needs at least one name')
      else
        Die('queue needs at least one file');
    if O.QRequest and (O.BsoDir = '') then
      Die('file requests need a BSO outbound (-O)');
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
{ A BSO or an attach style spool is in use. }
function UseSpool(const O : TOptions) : Boolean;
begin
  Result := (O.BsoDir <> '') or (O.MsgDir <> '');
end;

function MakeBso(const O : TOptions;
  const Fallback : TFTNAddress) : TBinkSpool;
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

  {$IFDEF MKMSG}
  if O.MsgDir <> '' then
  begin
    Result := TBinkAttachSpool.Create(
      O.MsgDir, O.AttachDir, Z, O.Config.Address);
    Exit;
  end;
  {$ENDIF}

  Result := TBinkBso.Create(O.BsoDir, Z);

  if O.HaveAddr then
    TBinkBso(Result).SetOwn(O.Config.Address);
end;

{ Plain directories are used when asked for with -o, or when there is
  no BSO spool. }
function UseFlat(const O : TOptions) : Boolean;
begin
  Result := O.OutDirSet or (not UseSpool(O));
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
  Bso  : TBinkSpool;
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

    if UseSpool(O) then
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

    if UseSpool(O) then
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

{$IFDEF UNIX}
procedure HandleRunSignal(Sig : cint); cdecl;
begin
  if GMailer = nil then
    Exit;

  if Sig = SIGHUP then
    GMailer.RequestReload
  else
    GMailer.Stop;
end;
{$ENDIF}

function DoRun(var O : TOptions) : Integer;
var
  Lg : TLog;
begin
  Lg := TLog.Create;
  GMailer := TBinkMailer.Create(O.LinksFile, @Lg.Print);
  GMailer.ControlPath := O.ControlSock;
  try
    {$IFDEF UNIX}
    fpSignal(SIGINT,  @HandleRunSignal);
    fpSignal(SIGTERM, @HandleRunSignal);
    fpSignal(SIGHUP,  @HandleRunSignal);
    {$ENDIF}
    Result := GMailer.Run;
  finally
    FreeAndNil(GMailer);
    Lg.Free;
  end;
end;

function DoCheck(var O : TOptions) : Integer;
var
  S : TBinkSetup;
  Errs, Warns : TStringList;
  I : Integer;
  L : TBinkLink;
begin
  S := TBinkSetup.Create;
  Errs := TStringList.Create;
  Warns := TStringList.Create;
  try
    if S.LoadFromFile(O.LinksFile, Errs, Warns) then
      Result := 0
    else
      Result := 1;

    for I := 0 to Warns.Count - 1 do
      Writeln('warning: ', Warns[I]);

    for I := 0 to Errs.Count - 1 do
      Writeln('error: ', Errs[I]);

    if Result <> 0 then
      Exit;

    for I := 0 to High(S.Addresses) do
      Writeln('address ', AddressToString(S.Addresses[I]));

    if S.Netmail <> '' then
      Writeln('inbound ', S.Inbound, '   netmail ', S.Netmail, '   attach ',
        S.AttachDir, '   zone ', S.BsoZone)
    else
      Writeln('inbound ', S.Inbound, '   bso ', S.Bso, '   zone ', S.BsoZone);
    Writeln('listen ', BoolToStr(S.Listen, 'yes', 'no'), '   port ', S.Port,
      '   bind ', S.Bind);

    for I := 0 to S.LinkCount - 1 do
    begin
      L := S.Links[I];
      Writeln('link ', AddressToString(L.Address), '  host ', L.Host, ':',
        L.Port, '  poll ', L.PollMin, '  answer-only ',
        BoolToStr(L.AnswerOnly, 'yes', 'no'), '  name ', L.Name);
    end;

    Writeln('ok: ', S.LinkCount, ' link(s)');
  finally
    Warns.Free;
    Errs.Free;
    S.Free;
  end;
end;

function DoQueue(var O : TOptions) : Integer;
var
  Target : TFTNAddress;
  Bso    : TBinkSpool;
  I      : Integer;
  Flow   : String;
  Pw, Nm : String;
  Act    : TBinkOutAction;
begin
  Target := ParseAddress(O.QTarget);
  Bso := MakeBso(O, Target);
  try
    if O.QRequest then
    begin
      I := 0;

      while I < O.QFiles.Count do
      begin
        if O.QFiles[I][1] = '!' then
          Die('A password (' + O.QFiles[I] + ') must follow the name it is for');

        Nm := O.QFiles[I];
        Pw := '';

        if (I + 1 < O.QFiles.Count) and (O.QFiles[I + 1][1] = '!') then
        begin
          Pw := Copy(O.QFiles[I + 1], 2, MaxInt);
          Inc(I);

          if Pw = '' then
            Die('"!" needs the password after it (for ' + Nm + ')');
        end;

        Flow := Bso.Request(Target, Nm, Pw);

        Writeln(Format('Requested %s from %s -> %s',
          [Nm, AddressToString(Target), Flow]));
        Inc(I);
      end;

      Result := 0;
      Exit;
    end;

    if O.QDelete then
      Act := oaDelete
    else if O.QTruncate then
      Act := oaTruncate
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
    else if Opts.Mode = 'run' then
      Halt(DoRun(Opts))
    else if Opts.Mode = 'check' then
      Halt(DoCheck(Opts))
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
