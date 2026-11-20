unit BinkBso;

{$mode objfpc}{$H+}

{ BinkleyTerm Style Outbound (BSO), as used by binkd, so that a tosser
  and the mailer can share one spool.

  Layout, for a base directory <base> and a default zone Z:

    <base>                 files for zone Z  (the default zone)
    <base>.zzz             files for any other zone, zzz = 3 hex digits
    <net><node>.ext        a system, net and node as 4 hex digits each
    <net><node>.pnt/<point>.ext   a point, point as 8 hex digits

  Extensions (flavours, most urgent first):

    flavour      flow file    netmail packet
    immediate    .ilo         .iut
    crash        .clo         .cut
    direct       .dlo         .dut
    normal       .flo         .out
    hold         .hlo         .hut     (sent only when THEY call US)
    busy flag    .bsy

  A flow file is a text file with one file per line.  A leading
  character says what to do after the file was sent:

    ^file   delete it        #file   truncate it to 0 bytes
    file    leave it         ~file   already sent, skip

  Netmail packets (.out etc.) are sent as <hex>.pkt and deleted.

  File requests (FTS-0006): <net><node>.req holds one request per
  line, "name" or "name !password" (password of 6 characters or
  fewer), written with Request.  It counts as normal mail: a call is made
  for it, and it is sent as <our net><our node>.req (the remote knows
  who asked from the file name, and from the session) and deleted when
  the remote has it.  Answering a request is the job of whoever receives
  the file (see on-freq in the settings file). }

interface

uses
  Classes,
  SysUtils,
  BinkTypes,
  BinkNode,
  BinkOutbound,
  BinkSpool;

type
  TBinkBso = class(TBinkSpool)
  private
    FBase        : String;
    FDefaultZone : Word;
    FOwn         : TFTNAddress;
    FHaveOwn     : Boolean;

    function PacketName : String;
    function RequestName(const A : TFTNAddress) : String;

  public
    constructor Create(const ABase : String; ADefaultZone : Word);

    { directory holding the zone's files / the system's files }
    function ZoneDir(Zone : Word) : String;
    function LinkDir(const A : TFTNAddress) : String;

    { file name without extension: 006e0122 or the point's 0000000a }
    function LinkStem(const A : TFTNAddress) : String;

    { .bsy flag for A.  TryLock fails if another session (or process)
      holds it; a flag left by a dead process, or older than 12 hours,
      is stale and is taken over. }
    function  TryLock(const A : TFTNAddress) : Boolean; override;
    procedure Unlock(const A : TFTNAddress); override;

    { Adds everything queued for A to Dest, most urgent flavour
      first.  Hold is only included when IncludeHold is set (they
      are calling us).  Returns the number of items added. }
    function Collect(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      Dest : TBinkOutbound) : Integer; override;

    { How many items Collect would find for A (nothing is changed). }
    function Pending(
      const A : TFTNAddress;
      IncludeHold : Boolean) : Integer; override;

    { Like Pending, and the size of the files in Bytes. }
    function PendingInfo(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      out Bytes : Int64) : Integer; override;

    { Queues FileName for A: appends it to the flow file of the given
      flavour (I, C, D, N or H).  Returns the flow file's path. }
    function Attach(
      const A : TFTNAddress;
      const FileName : String;
      Flavour : Char;
      Action : TBinkOutAction) : String; override;

    { Our address: a .req is sent under our net and node.  Without
      it the name of the link is used. }
    procedure SetOwn(const A : TFTNAddress);

    function Request(
      const A : TFTNAddress;
      const Name, Password : String) : String; override;

    property Base : String read FBase;
    property DefaultZone : Word read FDefaultZone;
  end;

implementation

uses
  {$IFDEF UNIX}
  BaseUnix,
  {$ENDIF}
  DateUtils,
  BinkUtil;

const
  STALE_LOCK_SECONDS = 12 * 3600;

  { flavour order = sending order }
  FLOW_EXT : array[0..4] of String = ('ilo', 'clo', 'dlo', 'flo', 'hlo');
  PKT_EXT  : array[0..4] of String = ('iut', 'cut', 'dut', 'out', 'hut');
  FLAVOURS = 'ICDNH';
  HOLD_RANK = 4;

var
  GPacketSeq : Integer = 0;

constructor TBinkBso.Create(const ABase : String; ADefaultZone : Word);
begin
  inherited Create;
  FBase := ExcludeTrailingPathDelimiter(ABase);
  FDefaultZone := ADefaultZone;
end;

function TBinkBso.ZoneDir(Zone : Word) : String;
begin
  if Zone = FDefaultZone then
    Result := FBase
  else
    Result := FBase + '.' + LowerCase(IntToHex(Zone, 3));
end;

function TBinkBso.LinkDir(const A : TFTNAddress) : String;
begin
  Result := ZoneDir(A.Zone);

  if A.Point <> 0 then
    Result := Result + PathDelim +
      LowerCase(IntToHex(A.Net, 4) + IntToHex(A.Node, 4)) + '.pnt';
end;

function TBinkBso.LinkStem(const A : TFTNAddress) : String;
begin
  if A.Point <> 0 then
    Result := LowerCase(IntToHex(A.Point, 8))
  else
    Result := LowerCase(IntToHex(A.Net, 4) + IntToHex(A.Node, 4));
end;

{ ------------------------------------------------------------------ }

function TBinkBso.TryLock(const A : TFTNAddress) : Boolean;
begin
  Result := TryLockFile(LinkDir(A) + PathDelim + LinkStem(A) + '.bsy');
end;

procedure TBinkBso.Unlock(const A : TFTNAddress);
begin
  DeleteFile(LinkDir(A) + PathDelim + LinkStem(A) + '.bsy');
end;

{ ------------------------------------------------------------------ }

procedure TBinkBso.SetOwn(const A : TFTNAddress);
begin
  FOwn := A;
  FHaveOwn := True;
end;

function TBinkBso.RequestName(const A : TFTNAddress) : String;
begin
  if FHaveOwn then
    Result := LowerCase(IntToHex(FOwn.Net, 4) + IntToHex(FOwn.Node, 4)) + '.req'
  else
    Result := LowerCase(IntToHex(A.Net, 4) + IntToHex(A.Node, 4)) + '.req';
end;

function TBinkBso.PacketName : String;
var
  N : Integer;
begin
  N := InterlockedIncrement(GPacketSeq);
  Result := LowerCase(IntToHex(
    Cardinal(DateTimeToUnix(Now)) + Cardinal(N), 8)) + '.pkt';
end;

function TBinkBso.Collect(
  const A : TFTNAddress;
  IncludeHold : Boolean;
  Dest : TBinkOutbound) : Integer;
var
  Dir, Stem, Name, Ext, L, Path : String;
  SR     : TSearchRec;
  Found  : TStringList;
  Flow   : TStringList;
  I, J, K, Rank : Integer;
  IsFlow : Boolean;
  Act    : TBinkOutAction;
  Sz     : Int64;
begin
  Result := 0;
  Dir := LinkDir(A);

  if not DirectoryExists(Dir) then
    Exit;

  Stem := LinkStem(A);
  Found := TStringList.Create;
  Flow  := TStringList.Create;
  try
    { key: rank, kind (flow before packet), name }
    if FindFirst(Dir + PathDelim + '*', faAnyFile, SR) = 0 then
    begin
      repeat
        if (SR.Attr and faDirectory) <> 0 then
          Continue;

        Name := LowerCase(SR.Name);

        if Copy(Name, 1, Length(Stem) + 1) <> Stem + '.' then
          Continue;

        Ext := Copy(Name, Length(Stem) + 2, 10);

        for K := 0 to 4 do
        begin
          if Ext = FLOW_EXT[K] then
            Found.Add(Format('%d1%s', [K, SR.Name]));

          if Ext = PKT_EXT[K] then
            Found.Add(Format('%d2%s', [K, SR.Name]));
        end;

        { a file request counts as normal mail }
        if Ext = 'req' then
          Found.Add(Format('33%s', [SR.Name]));
      until FindNext(SR) <> 0;

      FindClose(SR);
    end;

    Found.Sort;

    for I := 0 to Found.Count - 1 do
    begin
      Rank   := StrToInt(Found[I][1]);
      IsFlow := Found[I][2] = '1';
      Name   := Copy(Found[I], 3, MaxInt);
      Path   := Dir + PathDelim + Name;

      if (Rank = HOLD_RANK) and (not IncludeHold) then
        Continue;

      if Found[I][2] = '3' then
      begin
        { an empty request file is nothing to send }
        if FindFirst(Path, faAnyFile, SR) = 0 then
        begin
          Sz := SR.Size;
          FindClose(SR);
        end
        else
          Sz := 0;

        if Sz > 0 then
        begin
          Dest.AddItem(Path, RequestName(A), oaDelete);
          Inc(Result);
        end;
        Continue;
      end;

      if not IsFlow then
      begin
        Dest.AddItem(Path, PacketName, oaDelete);
        Inc(Result);
        Continue;
      end;

      Flow.Clear;

      try
        Flow.LoadFromFile(Path);
      except
        Continue;
      end;

      for J := 0 to Flow.Count - 1 do
      begin
        L := Trim(Flow[J]);

        if L = '' then
          Continue;

        case L[1] of
          '~' : Continue;            { already sent }
          '^' : begin Act := oaDelete;   Path := Trim(Copy(L, 2, MaxInt)); end;
          '#' : begin Act := oaTruncate; Path := Trim(Copy(L, 2, MaxInt)); end;
          '@' : begin Act := oaKeep;     Path := Trim(Copy(L, 2, MaxInt)); end;
        else
          Act := oaKeep;
          Path := L;
        end;

        if (Path = '') or (not FileExists(Path)) then
          Continue;

        Dest.AddItem(
          Path, ExtractFileName(Path), Act,
          Dir + PathDelim + Name, L);
        Inc(Result);
      end;
    end;
  finally
    Flow.Free;
    Found.Free;
  end;
end;

function TBinkBso.Pending(
  const A : TFTNAddress;
  IncludeHold : Boolean) : Integer;
var
  Tmp : TBinkOutbound;
begin
  Tmp := TBinkOutbound.Create;
  try
    Result := Collect(A, IncludeHold, Tmp);
  finally
    Tmp.Free;
  end;
end;

function TBinkBso.PendingInfo(
  const A : TFTNAddress;
  IncludeHold : Boolean;
  out Bytes : Int64) : Integer;
var
  Tmp : TBinkOutbound;
  I   : Integer;
  Sz  : Int64;
  SR  : TSearchRec;
begin
  Bytes := 0;
  Tmp := TBinkOutbound.Create;
  try
    Result := Collect(A, IncludeHold, Tmp);

    for I := 0 to Tmp.Count - 1 do
    begin
      Sz := 0;

      if FindFirst(Tmp.Items[I].LocalPath, faAnyFile, SR) = 0 then
      begin
        Sz := SR.Size;
        FindClose(SR);
      end;

      Inc(Bytes, Sz);
    end;
  finally
    Tmp.Free;
  end;
end;

function TBinkBso.Attach(
  const A : TFTNAddress;
  const FileName : String;
  Flavour : Char;
  Action : TBinkOutAction) : String;
var
  P : Integer;
  F : TextFile;
  Prefix : String;
begin
  P := Pos(UpCase(Flavour), FLAVOURS);

  if P = 0 then
    raise EBinkError.CreateFmt(
      'Unknown flavour "%s" (use I, C, D, N or H)', [Flavour]);

  if not FileExists(FileName) then
    raise EBinkError.CreateFmt('No such file: %s', [FileName]);

  case Action of
    oaDelete   : Prefix := '^';
    oaTruncate : Prefix := '#';
  else
    Prefix := '';
  end;

  ForceDirectories(LinkDir(A));

  Result := LinkDir(A) + PathDelim + LinkStem(A) + '.' + FLOW_EXT[P - 1];

  AssignFile(F, Result);

  if FileExists(Result) then
    Append(F)
  else
    Rewrite(F);

  try
    Writeln(F, Prefix + ExpandFileName(FileName));
  finally
    CloseFile(F);
  end;
end;


function TBinkBso.Request(
  const A : TFTNAddress;
  const Name, Password : String) : String;
var
  Lines : TStringList;
  Line, Have : String;
  I, P : Integer;
  F : TextFile;
begin
  if Name = '' then
    raise EBinkError.Create('A file request needs a name');

  for I := 1 to Length(Name) do
    if (Name[I] <= ' ') or (Name[I] = '!') or (Name[I] = '/') or
       (Name[I] = '\') or (Ord(Name[I]) > 126) then
      raise EBinkError.CreateFmt(
        'The name "%s" cannot be requested (no blanks, !, slashes or ' +
        'control characters)', [Name]);

  if Length(Password) > 6 then
    raise EBinkError.CreateFmt(
      'The password for %s is longer than 6 characters: FTS-0006 does ' +
      'not allow that', [Name]);

  for I := 1 to Length(Password) do
    if (Password[I] <= ' ') or (Ord(Password[I]) > 126) then
      raise EBinkError.CreateFmt(
        'The password for %s has a blank or a control character', [Name]);

  Line := Name;

  if Password <> '' then
    Line := Line + ' !' + Password;

  ForceDirectories(LinkDir(A));

  Result := LinkDir(A) + PathDelim + LinkStem(A) + '.req';

  { a request that is waiting already is not written twice }
  if FileExists(Result) then
  begin
    Lines := TStringList.Create;
    try
      try
        Lines.LoadFromFile(Result);
      except
        Lines.Clear;
      end;

      for I := 0 to Lines.Count - 1 do
      begin
        Have := Trim(Lines[I]);
        P := Pos(' !', Have);

        if P > 0 then
          Have := Copy(Have, 1, P - 1) + ' !' + Trim(Copy(Have, P + 2, MaxInt));

        if SameText(Have, Line) then
          Exit;
      end;
    finally
      Lines.Free;
    end;
  end;

  AssignFile(F, Result);

  if FileExists(Result) then
    Append(F)
  else
    Rewrite(F);

  try
    { the spec ends a line with CR; LF after it is what readers that use
      ReadLn need, and the others skip it }
    Write(F, Line + #13#10);
  finally
    CloseFile(F);
  end;
end;

end.
