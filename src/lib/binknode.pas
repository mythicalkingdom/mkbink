{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkNode;

{$mode objfpc}{$H+}

interface

uses
  BinkTypes;

{ Parses  zone:net/node[.point][@domain]  (3D, 4D or 5D).
  Returns False on malformed input. }
function TryParseAddress(const S: String;
  out A: TFTNAddress): Boolean;

{ Same, but raises EBinkError on malformed input. }
function ParseAddress(const S: String): TFTNAddress;

{ Parses a space separated M_ADR argument list.  Malformed entries
  are skipped.  Returns the number of addresses parsed. }
function ParseAddressList(const S: String;
  out List: array of TFTNAddress): Integer;

{ zone:net/node.point }
function AddressToString(const A: TFTNAddress): String;

{ zone:net/node.point@domain  (domain omitted when empty) }
function AddressToString5D(const A: TFTNAddress;
  const Domain: String): String;

function SameAddress(const A, B: TFTNAddress): Boolean;

{ zone.net.node.point  -- usable as a directory name. }
function AddressToDirName(const A: TFTNAddress): String;

implementation

uses
  SysUtils;

function TryWord(const S: String; out W: Word): Boolean;
var
  V : LongInt;
begin
  Result := False;

  if (S = '') or (Length(S) > 5) then
    Exit;

  if not TryStrToInt(S, V) then
    Exit;

  if (V < 0) or (V > 65535) then
    Exit;

  W := V;
  Result := True;
end;

function TryParseAddress(const S: String;
  out A: TFTNAddress): Boolean;
var
  T : String;
  P : Integer;
begin
  Result := False;
  FillChar(A, SizeOf(A), 0);

  T := Trim(S);

  { strip @domain }
  P := Pos('@', T);
  if P > 0 then
    T := Copy(T, 1, P - 1);

  P := Pos(':', T);
  if P < 2 then
    Exit;
  if not TryWord(Copy(T, 1, P - 1), A.Zone) then
    Exit;
  Delete(T, 1, P);

  P := Pos('/', T);
  if P < 2 then
    Exit;
  if not TryWord(Copy(T, 1, P - 1), A.Net) then
    Exit;
  Delete(T, 1, P);

  P := Pos('.', T);
  if P = 0 then
  begin
    if not TryWord(T, A.Node) then
      Exit;
  end
  else
  begin
    if not TryWord(Copy(T, 1, P - 1), A.Node) then
      Exit;
    if not TryWord(Copy(T, P + 1, 255), A.Point) then
      Exit;
  end;

  Result := True;
end;

function ParseAddress(const S: String): TFTNAddress;
begin
  if not TryParseAddress(S, Result) then
    raise EBinkError.CreateFmt('Invalid FTN address "%s"', [S]);
end;

function ParseAddressList(const S: String;
  out List: array of TFTNAddress): Integer;
var
  I        : Integer;
  Item     : String;
  A        : TFTNAddress;

  procedure Flush;
  begin
    if Item = '' then
      Exit;

    if (Result <= High(List)) and TryParseAddress(Item, A) then
    begin
      List[Result] := A;
      Inc(Result);
    end;

    Item := '';
  end;

begin
  Result := 0;
  Item   := '';

  for I := 1 to Length(S) do
  begin
    if S[I] in [' ', #9, #0] then
      Flush
    else
      Item := Item + S[I];
  end;

  Flush;
end;

function AddressToString(const A : TFTNAddress): String;
begin
  Result := Format('%d:%d/%d.%d',
    [A.Zone, A.Net, A.Node, A.Point]);
end;

function AddressToString5D(const A: TFTNAddress;
  const Domain: String): String;
begin
  Result := AddressToString(A);

  if Domain <> '' then
    Result := Result + '@' + Domain;
end;

function SameAddress(const A, B: TFTNAddress): Boolean;
begin
  Result :=
    (A.Zone = B.Zone) and (A.Net = B.Net) and
    (A.Node = B.Node) and (A.Point = B.Point);
end;

function AddressToDirName(const A: TFTNAddress): String;
begin
  Result := Format('%d.%d.%d.%d',
    [A.Zone, A.Net, A.Node, A.Point]);
end;

end.
