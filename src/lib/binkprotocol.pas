unit BinkProtocol;

{$mode objfpc}{$H+}

{ binkp command identifiers and command argument helpers
  (FTS-1026 section 5). }

interface

uses
  Classes,
  SysUtils;

const
  M_NUL  = 0;
  M_ADR  = 1;
  M_PWD  = 2;
  M_FILE = 3;
  M_OK   = 4;
  M_EOB  = 5;
  M_GOT  = 6;
  M_ERR  = 7;
  M_BSY  = 8;
  M_GET  = 9;
  M_SKIP = 10;

type

  TBinkCommand =
  (
    bcUnknown,
    bcNUL,
    bcADR,
    bcPWD,
    bcFILE,
    bcOK,
    bcEOB,
    bcGOT,
    bcERR,
    bcBSY,
    bcGET,
    bcSKIP
  );

  { File parameters shared by M_FILE, M_GET, M_GOT and M_SKIP:
    "name size unixtime [offset]".  FileName is stored unescaped.
    For M_GOT / M_SKIP, Size and TimeStamp are -1 when the remote did
    not supply them.

    NR: the offset was -1 (FTS-1028 non-reliable mode): the sender is
        waiting for an M_GET that says where to start.  Offset is 0.
    NZ: an M_GET carried the "NZ" word, which switches PLZ compression
        off (FTS-1029). }
  TBinkFileInfo = record
    FileName : String;
    Size     : Int64;
    TimeStamp: Int64;
    Offset   : Int64;
    NR       : Boolean;
    NZ       : Boolean;
  end;

function CommandToID(
  Cmd : TBinkCommand) : Byte;

function IDToCommand(
  ID : Byte) : TBinkCommand;

function CommandName(
  Cmd : TBinkCommand) : String;

{ Section 5.2 / 5.4: space, backslash and anything outside the "safe"
  printable ASCII set is sent as \xHH. }
function EscapeFileName(
  const S : String) : String;

{ Decodes \xHH, and (for compatibility with FSP-1011.003 mailers) \HH. }
function UnescapeFileName(
  const S : String) : String;

function ParseFILE(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;

function BuildFILE(
  const Info : TBinkFileInfo) : String;

function ParseGET(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;

function BuildGET(
  const Info : TBinkFileInfo) : String;

function ParseGOT(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;

function BuildGOT(
  const Info : TBinkFileInfo) : String;

function ParseSKIP(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;

function BuildSKIP(
  const Info : TBinkFileInfo) : String;

implementation

function CommandToID(
  Cmd : TBinkCommand) : Byte;
begin
  case Cmd of
    bcNUL  : Result := M_NUL;
    bcADR  : Result := M_ADR;
    bcPWD  : Result := M_PWD;
    bcFILE : Result := M_FILE;
    bcOK   : Result := M_OK;
    bcEOB  : Result := M_EOB;
    bcGOT  : Result := M_GOT;
    bcERR  : Result := M_ERR;
    bcBSY  : Result := M_BSY;
    bcGET  : Result := M_GET;
    bcSKIP : Result := M_SKIP;
  else
    Result := 255;
  end;
end;

function IDToCommand(
  ID : Byte) : TBinkCommand;
begin
  case ID of
    M_NUL  : Result := bcNUL;
    M_ADR  : Result := bcADR;
    M_PWD  : Result := bcPWD;
    M_FILE : Result := bcFILE;
    M_OK   : Result := bcOK;
    M_EOB  : Result := bcEOB;
    M_GOT  : Result := bcGOT;
    M_ERR  : Result := bcERR;
    M_BSY  : Result := bcBSY;
    M_GET  : Result := bcGET;
    M_SKIP : Result := bcSKIP;
  else
    Result := bcUnknown;
  end;
end;

function CommandName(
  Cmd : TBinkCommand) : String;
begin
  case Cmd of
    bcNUL  : Result := 'M_NUL';
    bcADR  : Result := 'M_ADR';
    bcPWD  : Result := 'M_PWD';
    bcFILE : Result := 'M_FILE';
    bcOK   : Result := 'M_OK';
    bcEOB  : Result := 'M_EOB';
    bcGOT  : Result := 'M_GOT';
    bcERR  : Result := 'M_ERR';
    bcBSY  : Result := 'M_BSY';
    bcGET  : Result := 'M_GET';
    bcSKIP : Result := 'M_SKIP';
  else
    Result := 'UNKNOWN';
  end;
end;

{ ------------------------------------------------------------------ }

function EscapeFileName(
  const S : String) : String;
var
  I : Integer;
  C : Char;
begin
  Result := '';

  for I := 1 to Length(S) do
  begin
    C := S[I];

    { printable ASCII except space and backslash is "safe" }
    if (C > ' ') and (C < #127) and (C <> '\') then
      Result := Result + C
    else
      Result := Result + '\x' + LowerCase(IntToHex(Ord(C), 2));
  end;
end;

function HexVal(C : Char) : Integer;
begin
  case C of
    '0'..'9' : Result := Ord(C) - Ord('0');
    'a'..'f' : Result := Ord(C) - Ord('a') + 10;
    'A'..'F' : Result := Ord(C) - Ord('A') + 10;
  else
    Result := -1;
  end;
end;

function UnescapeFileName(
  const S : String) : String;
var
  I, H, L : Integer;
begin
  Result := '';
  I := 1;

  while I <= Length(S) do
  begin
    if S[I] = '\' then
    begin
      { \xHH }
      if (I + 3 <= Length(S)) and (S[I + 1] in ['x', 'X']) then
      begin
        H := HexVal(S[I + 2]);
        L := HexVal(S[I + 3]);

        if (H >= 0) and (L >= 0) then
        begin
          Result := Result + Chr(H * 16 + L);
          Inc(I, 4);
          Continue;
        end;
      end;

      { legacy \HH }
      if I + 2 <= Length(S) then
      begin
        H := HexVal(S[I + 1]);
        L := HexVal(S[I + 2]);

        if (H >= 0) and (L >= 0) then
        begin
          Result := Result + Chr(H * 16 + L);
          Inc(I, 3);
          Continue;
        end;
      end;
    end;

    Result := Result + S[I];
    Inc(I);
  end;
end;

{ ------------------------------------------------------------------ }

{ Splits on blanks.  Returns the number of words (at most 8). }
function SplitWords(
  const S : String;
  out W : array of String) : Integer;
var
  I : Integer;
  Cur : String;
begin
  Result := 0;
  Cur := '';

  for I := 1 to Length(S) + 1 do
  begin
    if (I > Length(S)) or (S[I] in [' ', #9, #0]) then
    begin
      if Cur <> '' then
      begin
        if Result <= High(W) then
        begin
          W[Result] := Cur;
          Inc(Result);
        end;

        Cur := '';
      end;
    end
    else
      Cur := Cur + S[I];
  end;
end;

{ Reads a decimal number the way M_FILE / M_GET do.  Returns False
  if the text looks like a number but is malformed or overflows. }
function LooksNumeric(const W : String) : Boolean;
var
  I : Integer;
begin
  Result := W <> '';

  for I := 1 to Length(W) do
    if not (W[I] in ['0'..'9', '-']) then
      Exit(False);
end;

{ Common parser: "name size time [offset] [flags...]". MinWords is 3
  for M_FILE / M_GET and 1 for M_GOT / M_SKIP.  Numbers must be
  decimal, non negative and must not overflow.  An offset of -1 is the
  non-reliable-mode marker (NR).  Words after the three numbers are
  option flags from protocol extensions: "NZ" is recognised, any other
  word is ignored. }
function ParseFileArgs(
  const S : String;
  MinWords : Integer;
  out Info : TBinkFileInfo) : Boolean;
var
  W : array[0..7] of String;
  N, I : Integer;
  GotOffset : Boolean;
  V : Int64;
begin
  Result := False;

  Info.FileName  := '';
  Info.Size      := -1;
  Info.TimeStamp := -1;
  Info.Offset    := 0;
  Info.NR        := False;
  Info.NZ        := False;

  N := SplitWords(S, W);

  if N < MinWords then
    Exit;

  Info.FileName := UnescapeFileName(W[0]);

  if Info.FileName = '' then
    Exit;

  if N > 1 then
  begin
    if not TryStrToInt64(W[1], Info.Size) then Exit;
    if Info.Size < 0 then Exit;
  end;

  if N > 2 then
  begin
    if not TryStrToInt64(W[2], Info.TimeStamp) then Exit;
    if Info.TimeStamp < 0 then Exit;
  end;

  GotOffset := False;

  for I := 3 to N - 1 do
  begin
    if UpperCase(W[I]) = 'NZ' then
      Info.NZ := True
    else if (not GotOffset) and LooksNumeric(W[I]) then
    begin
      if not TryStrToInt64(W[I], V) then Exit;   { overflow / junk }

      if V < 0 then
        Info.NR := True    { -1: sender waits for our M_GET }
      else
        Info.Offset := V;

      GotOffset := True;
    end;
    { any other word: flag of an extension we do not know, ignore }
  end;

  Result := True;
end;

function BuildFileArgs(
  const Info : TBinkFileInfo;
  WithOffset : Boolean) : String;
begin
  Result := Format('%s %d %d',
    [EscapeFileName(Info.FileName), Info.Size, Info.TimeStamp]);

  if WithOffset then
  begin
    if Info.NR then
      Result := Result + ' -1'
    else
      Result := Result + ' ' + IntToStr(Info.Offset);
  end;
end;

function ParseFILE(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;
begin
  Result := ParseFileArgs(S, 3, Info);
end;

function BuildFILE(
  const Info : TBinkFileInfo) : String;
begin
  Result := BuildFileArgs(Info, True);
end;

function ParseGET(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;
begin
  Result := ParseFileArgs(S, 3, Info);
end;

function BuildGET(
  const Info : TBinkFileInfo) : String;
var
  G : TBinkFileInfo;
begin
  G := Info;
  G.NR := False;   { a GET always carries a real offset }
  Result := BuildFileArgs(G, True);

  if Info.NZ then
    Result := Result + ' NZ';
end;

function ParseGOT(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;
begin
  Result := ParseFileArgs(S, 1, Info);
end;

function BuildGOT(
  const Info : TBinkFileInfo) : String;
begin
  Result := BuildFileArgs(Info, False);
end;

function ParseSKIP(
  const S : String;
  out Info : TBinkFileInfo) : Boolean;
begin
  Result := ParseFileArgs(S, 1, Info);
end;

function BuildSKIP(
  const Info : TBinkFileInfo) : String;
begin
  Result := BuildFileArgs(Info, False);
end;

end.
