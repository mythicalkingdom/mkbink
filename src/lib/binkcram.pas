unit BinkCram;

{$mode objfpc}{$H+}

{ CRAM authentication for binkp (FTS-1027).

    answering side:   M_NUL "OPT CRAM-<hash list>-<challenge hex>"
    originating side: M_PWD "CRAM-<chosen hash>-<hex HMAC(password, challenge)>"

  <hash list> is a slash separated list of aliases, most preferred
  first (MD5, SHA1).  The challenge is sent as hex text but the HMAC
  is computed over the decoded challenge bytes (RFC 2104). }

interface

const
  CRAM_PREFIX = 'CRAM-';

{ lowercase hex of HMAC(Key, Data) with Hash = 'MD5' or 'SHA1'.
  Returns '' for an unsupported hash. }
function HmacHex(const Hash, Key, Data : String) : String;

{ compatibility wrapper: HMAC-MD5 }
function HmacMD5Hex(const Key, Data : String) : String;

{ 16 random bytes as 32 lowercase hex digits. }
function NewChallenge : String;

{ Hex text -> raw bytes in a string.  Returns False if Hex is not an
  even length string of hex digits. }
function HexToBytes(const Hex : String; out Bytes : String) : Boolean;

{ The M_PWD argument  CRAM-<Hash>-<digest>  or '' if the challenge is
  malformed or the hash unsupported. }
function CramPassword(
  const Password, Hash, ChallengeHex : String) : String;

{ Looks through the words of an "OPT ..." argument for
  CRAM-<list>-<hex>.  Chooses the first hash in the list that we
  support.  Returns False if there is no usable challenge. }
function FindChallenge(
  const OptArgs : String;
  out Hash, ChallengeHex : String) : Boolean;

{ Answering side: checks the first word of an M_PWD argument against
  the challenge we sent.  Any words after the digest are ignored. }
function CramVerify(
  const Password, ChallengeHex, Received : String) : Boolean;

implementation

uses
  SysUtils,
  md5,
  sha1;

function HashRaw(const Hash, S : String) : String;
var
  M : TMDDigest;
  H : TSHA1Digest;
begin
  Result := '';

  if Hash = 'MD5' then
  begin
    M := MD5String(S);
    SetLength(Result, 16);
    Move(M, Result[1], 16);
  end
  else if Hash = 'SHA1' then
  begin
    H := SHA1String(S);
    SetLength(Result, 20);
    Move(H, Result[1], 20);
  end;
end;

function HmacHex(const Hash, Key, Data : String) : String;
var
  K, IPad, OPad, D : String;
  I : Integer;
begin
  Result := '';

  if (Hash <> 'MD5') and (Hash <> 'SHA1') then
    Exit;

  K := Key;

  { the block size of both MD5 and SHA-1 is 64 bytes }
  if Length(K) > 64 then
    K := HashRaw(Hash, K);

  SetLength(IPad, 64);
  SetLength(OPad, 64);

  for I := 1 to 64 do
  begin
    if I <= Length(K) then
    begin
      IPad[I] := Chr(Ord(K[I]) xor $36);
      OPad[I] := Chr(Ord(K[I]) xor $5C);
    end
    else
    begin
      IPad[I] := Chr($36);
      OPad[I] := Chr($5C);
    end;
  end;

  D := HashRaw(Hash, OPad + HashRaw(Hash, IPad + Data));

  for I := 1 to Length(D) do
    Result := Result + LowerCase(IntToHex(Ord(D[I]), 2));
end;

function HmacMD5Hex(const Key, Data : String) : String;
begin
  Result := HmacHex('MD5', Key, Data);
end;

function NewChallenge : String;
var
  F : File of Byte;
  B : array[0..15] of Byte;
  I, N : Integer;
  Got : Boolean;
begin
  Got := False;

  {$IFDEF UNIX}
  AssignFile(F, '/dev/urandom');
  {$I-}
  Reset(F);
  {$I+}

  if IOResult = 0 then
  begin
    N := 0;
    {$I-}
    BlockRead(F, B, SizeOf(B), N);
    {$I+}
    CloseFile(F);
    Got := N = SizeOf(B);
  end;
  {$ENDIF}

  if not Got then
  begin
    { weak fallback }
    Randomize;

    for I := 0 to 15 do
      B[I] := Random(256);
  end;

  Result := '';

  for I := 0 to 15 do
    Result := Result + LowerCase(IntToHex(B[I], 2));
end;

function HexToBytes(const Hex : String; out Bytes : String) : Boolean;
var
  I, H, L : Integer;

  function V(C : Char) : Integer;
  begin
    case C of
      '0'..'9' : Result := Ord(C) - 48;
      'a'..'f' : Result := Ord(C) - 87;
      'A'..'F' : Result := Ord(C) - 55;
    else
      Result := -1;
    end;
  end;

begin
  Bytes := '';
  Result := False;

  if (Hex = '') or (Odd(Length(Hex))) then
    Exit;

  SetLength(Bytes, Length(Hex) div 2);

  for I := 0 to Length(Bytes) - 1 do
  begin
    H := V(Hex[I * 2 + 1]);
    L := V(Hex[I * 2 + 2]);

    if (H < 0) or (L < 0) then
    begin
      Bytes := '';
      Exit;
    end;

    Bytes[I + 1] := Chr(H * 16 + L);
  end;

  Result := True;
end;

function CramPassword(
  const Password, Hash, ChallengeHex : String) : String;
var
  Raw, D : String;
begin
  Result := '';

  if not HexToBytes(ChallengeHex, Raw) then
    Exit;

  D := HmacHex(Hash, Password, Raw);

  if D <> '' then
    Result := CRAM_PREFIX + Hash + '-' + D;
end;

function FindChallenge(
  const OptArgs : String;
  out Hash, ChallengeHex : String) : Boolean;
var
  I, P, Q : Integer;
  W, List, Hex, Raw, Alias : String;

  procedure Check;
  begin
    if (Length(W) > Length(CRAM_PREFIX)) and
       (CompareText(Copy(W, 1, Length(CRAM_PREFIX)), CRAM_PREFIX) = 0) and
       (not Result) then
    begin
      P := Pos('-', Copy(W, Length(CRAM_PREFIX) + 1, MaxInt));

      if P > 1 then
      begin
        List := UpperCase(Copy(W, Length(CRAM_PREFIX) + 1, P - 1));
        Hex  := Copy(W, Length(CRAM_PREFIX) + P + 1, MaxInt);

        if HexToBytes(Hex, Raw) then
        begin
          { first alias in the remote's preference order that we know }
          List := List + '/';

          while (List <> '') and (not Result) do
          begin
            Q := Pos('/', List);
            Alias := Copy(List, 1, Q - 1);
            Delete(List, 1, Q);

            if (Alias = 'MD5') or (Alias = 'SHA1') then
            begin
              Hash := Alias;
              ChallengeHex := LowerCase(Hex);
              Result := True;
            end;
          end;
        end;
      end;
    end;

    W := '';
  end;

begin
  Result := False;
  Hash := '';
  ChallengeHex := '';
  W := '';

  for I := 1 to Length(OptArgs) do
  begin
    if OptArgs[I] in [' ', #9, #0] then
      Check
    else
      W := W + OptArgs[I];
  end;

  Check;
end;

function CramVerify(
  const Password, ChallengeHex, Received : String) : Boolean;
var
  Word1, Hash, Want : String;
  P, I, D : Integer;
begin
  Result := False;

  Word1 := Trim(Received);
  P := Pos(' ', Word1);

  if P > 0 then
    Word1 := Copy(Word1, 1, P - 1);

  if CompareText(Copy(Word1, 1, Length(CRAM_PREFIX)), CRAM_PREFIX) <> 0 then
    Exit;

  Delete(Word1, 1, Length(CRAM_PREFIX));
  P := Pos('-', Word1);

  if P < 2 then
    Exit;

  Hash := UpperCase(Copy(Word1, 1, P - 1));
  Delete(Word1, 1, P);

  Want := CramPassword(Password, Hash, ChallengeHex);

  if Want = '' then
    Exit;

  Delete(Want, 1, Length(CRAM_PREFIX) + Length(Hash) + 1);
  Word1 := LowerCase(Word1);

  { constant time compare }
  D := Length(Want) xor Length(Word1);

  for I := 1 to Length(Want) do
    if I <= Length(Word1) then
      D := D or (Ord(Want[I]) xor Ord(Word1[I]));

  Result := D = 0;
end;

end.
