unit BinkCrypt;

{$mode objfpc}{$H+}
{$Q-}{$R-}

{ binkp CRYPT: the stream cipher used by binkd and Synchronet.

  It is the classic Info-ZIP "traditional" cipher: three 32-bit keys
  evolve with every plaintext byte.  The keys are seeded from the
  session password (not from the CRAM challenge).  The two directions
  of a session use different seeds, see InitCryptKeys.

  Weak by modern standards (known-plaintext attacks); it keeps casual
  sniffers out, nothing more. }

interface

type
  TBinkCipher = record
    K0, K1, K2 : Cardinal;
  end;

{ Seed from a password: the three constants, then every password byte
  run through the key update. }
procedure CipherInit(out C : TBinkCipher; const Password : String);

{ Seed the receive cipher: constants + "-", then the password bytes. }
procedure CipherInitDash(out C : TBinkCipher; const Password : String);

procedure CipherEncrypt(var C : TBinkCipher; var Buf; Len : Integer);
procedure CipherDecrypt(var C : TBinkCipher; var Buf; Len : Integer);

implementation

var
  CrcTable : array[0..255] of Cardinal;

procedure BuildTable;
var
  I, J : Integer;
  V : Cardinal;
begin
  for I := 0 to 255 do
  begin
    V := I;

    for J := 1 to 8 do
      if (V and 1) <> 0 then
        V := (V shr 1) xor $EDB88320
      else
        V := V shr 1;

    CrcTable[I] := V;
  end;
end;

function Crc32(Crc : Cardinal; B : Byte) : Cardinal; inline;
begin
  Result := CrcTable[(Crc xor B) and $FF] xor (Crc shr 8);
end;

procedure UpdateKeys(var C : TBinkCipher; B : Byte); inline;
begin
  C.K0 := Crc32(C.K0, B);
  C.K1 := C.K1 + (C.K0 and $FF);
  C.K1 := C.K1 * 134775813 + 1;
  C.K2 := Crc32(C.K2, C.K1 shr 24);
end;

function StreamByte(const C : TBinkCipher) : Byte; inline;
var
  T : Cardinal;
begin
  T := (C.K2 and $FFFF) or 2;
  Result := ((T * (T xor 1)) shr 8) and $FF;
end;

procedure Seed(out C : TBinkCipher);
begin
  C.K0 := 305419896;
  C.K1 := 591751049;
  C.K2 := 878082192;
end;

procedure CipherInit(out C : TBinkCipher; const Password : String);
var
  I : Integer;
begin
  Seed(C);

  for I := 1 to Length(Password) do
    UpdateKeys(C, Ord(Password[I]));
end;

procedure CipherInitDash(out C : TBinkCipher; const Password : String);
var
  I : Integer;
begin
  CipherInit(C, '-');

  for I := 1 to Length(Password) do
    UpdateKeys(C, Ord(Password[I]));
end;

procedure CipherEncrypt(var C : TBinkCipher; var Buf; Len : Integer);
var
  P : PByte;
  I : Integer;
  T, Plain : Byte;
begin
  P := @Buf;

  for I := 0 to Len - 1 do
  begin
    T := StreamByte(C);
    Plain := P[I];
    UpdateKeys(C, Plain);
    P[I] := Plain xor T;
  end;
end;

procedure CipherDecrypt(var C : TBinkCipher; var Buf; Len : Integer);
var
  P : PByte;
  I : Integer;
begin
  P := @Buf;

  for I := 0 to Len - 1 do
  begin
    P[I] := P[I] xor StreamByte(C);
    UpdateKeys(C, P[I]);
  end;
end;

initialization
  BuildTable;

end.
