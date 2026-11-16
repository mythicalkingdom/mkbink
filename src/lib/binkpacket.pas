unit BinkPacket;

{$mode objfpc}{$H+}

{ Writes FTN netmail packets (.pkt): a type 2+ packet header (FSC-0048,
  which carries zones and points) followed by type 2 messages
  (FTS-0001).  Everything is little endian on disk.

  Only what the attach-style outbound needs: no password, netmail text
  is passed through unchanged (the caller keeps the INTL/FMPT/TOPT
  kludges that are already in it). }

interface

uses
  Classes,
  SysUtils,
  BinkTypes;

const
  PKT_ATTR_PRIVATE = $0001;
  PKT_ATTR_CRASH   = $0002;
  PKT_ATTR_HOLD    = $0200;

type
  TBinkPacketWriter = class
  private
    FStream : TFileStream;
    FCount  : Integer;

    procedure PutWord(W : Word);
    procedure PutByte(B : Byte);
    procedure PutNul(const S : String; MaxLen : Integer);

  public
    { Creates Path.  Orig and Dest are the addresses of the packet
      itself (our address and the link's). }
    constructor Create(
      const Path : String;
      const Orig, Dest : TFTNAddress);
    destructor Destroy; override;

    { DateTime is "DD Mon YY  HH:MM:SS" (19 chars); anything else is
      replaced by the current time.  Attr is the FTS-0001 attribute
      word (the caller strips local flags such as Sent). }
    procedure AddMessage(
      const FromName, ToName, Subject, DateTime : String;
      const MsgOrig, MsgDest : TFTNAddress;
      Attr, Cost : Word;
      const Text : String);

    { Writes the terminator and closes the file. }
    procedure Close;

    property Count : Integer read FCount;
  end;

{ FTS-0001 date string for Now, e.g. "16 Nov 26  13:11:53". }
function PacketDateTime(T : TDateTime) : String;

implementation

const
  MONTHS : array[1..12] of String = (
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');

function PacketDateTime(T : TDateTime) : String;
var
  Y, Mo, D, H, Mi, S, Ms : Word;
begin
  DecodeDate(T, Y, Mo, D);
  DecodeTime(T, H, Mi, S, Ms);
  Result := Format('%.2d %s %.2d  %.2d:%.2d:%.2d',
    [D, MONTHS[Mo], Y mod 100, H, Mi, S]);
end;

procedure TBinkPacketWriter.PutByte(B : Byte);
begin
  FStream.WriteBuffer(B, 1);
end;

procedure TBinkPacketWriter.PutWord(W : Word);
begin
  PutByte(W and $FF);
  PutByte(W shr 8);
end;

{ NUL terminated string, truncated to MaxLen characters. }
procedure TBinkPacketWriter.PutNul(const S : String; MaxLen : Integer);
var
  T : String;
begin
  T := Copy(S, 1, MaxLen);

  if T <> '' then
    FStream.WriteBuffer(T[1], Length(T));

  PutByte(0);
end;

constructor TBinkPacketWriter.Create(
  const Path : String;
  const Orig, Dest : TFTNAddress);
var
  Y, Mo, D, H, Mi, S, Ms : Word;
  I : Integer;
begin
  inherited Create;
  FStream := TFileStream.Create(Path, fmCreate);
  FCount := 0;

  DecodeDate(Now, Y, Mo, D);
  DecodeTime(Now, H, Mi, S, Ms);

  PutWord(Orig.Node);              { 0  origNode }
  PutWord(Dest.Node);              { 2  destNode }
  PutWord(Y);                      { 4  year }
  PutWord(Mo - 1);                 { 6  month, 0 based }
  PutWord(D);                      { 8  day }
  PutWord(H);                      { 10 hour }
  PutWord(Mi);                     { 12 minute }
  PutWord(S);                      { 14 second }
  PutWord(0);                      { 16 baud }
  PutWord(2);                      { 18 packet type }
  PutWord(Orig.Net);               { 20 origNet }
  PutWord(Dest.Net);               { 22 destNet }
  PutByte($FE);                    { 24 product code, low (no code) }
  PutByte(1);                      { 25 revision, major }
  for I := 1 to 8 do               { 26 password }
    PutByte(0);
  PutWord(Orig.Zone);              { 34 qOrigZone }
  PutWord(Dest.Zone);              { 36 qDestZone }
  PutWord(Orig.Net);               { 38 auxNet }
  PutWord($0100);                  { 40 capability validation (swapped) }
  PutByte(0);                      { 42 product code, high }
  PutByte(0);                      { 43 revision, minor }
  PutWord($0001);                  { 44 capability word: type 2+ }
  PutWord(Orig.Zone);              { 46 origZone }
  PutWord(Dest.Zone);              { 48 destZone }
  PutWord(Orig.Point);             { 50 origPoint }
  PutWord(Dest.Point);             { 52 destPoint }
  PutWord(0);                      { 54 product specific data }
  PutWord(0);                      { 56 }
end;

destructor TBinkPacketWriter.Destroy;
begin
  FStream.Free;
  inherited Destroy;
end;

procedure TBinkPacketWriter.AddMessage(
  const FromName, ToName, Subject, DateTime : String;
  const MsgOrig, MsgDest : TFTNAddress;
  Attr, Cost : Word;
  const Text : String);
var
  Stamp : String;
  I : Integer;
begin
  Stamp := DateTime;

  if Length(Stamp) <> 19 then
    Stamp := PacketDateTime(Now);

  PutWord(2);                      { message type }
  PutWord(MsgOrig.Node);
  PutWord(MsgDest.Node);
  PutWord(MsgOrig.Net);
  PutWord(MsgDest.Net);
  PutWord(Attr);
  PutWord(Cost);

  for I := 1 to 19 do
    PutByte(Ord(Stamp[I]));

  PutByte(0);

  PutNul(ToName, 35);
  PutNul(FromName, 35);
  PutNul(Subject, 71);

  { the text must not contain a NUL }
  PutNul(StringReplace(Text, #0, ' ', [rfReplaceAll]), MaxInt);

  Inc(FCount);
end;

procedure TBinkPacketWriter.Close;
begin
  if FStream <> nil then
  begin
    PutWord(0);                    { end of packet }
    FreeAndNil(FStream);
  end;
end;

end.
