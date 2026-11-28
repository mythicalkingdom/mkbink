{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkFrame;

{$mode objfpc}{$H+}

{ binkp frame encoding / decoding (FTS-1026 section 4) and the
  dataframe compression header of FTS-1029 (PLZ).

    +-+-------------+--- ... ---+
    |T|  SIZE (15)  |   DATA    |      T=1: command frame
    +-+-------------+--- ... ---+      T=0: data frame

  For command frames the first DATA octet is the command ID.

  In PLZ mode bit 14 of the header marks a deflated data frame and
  SIZE is only 14 bits wide. }

interface

uses
  Classes,
  SysUtils,
  BinkTypes,
  BinkSocket;

const
  BINK_MAX_FRAME = 32767;

  { Largest data frame in PLZ mode (14 bit size field). }
  BINK_MAX_FRAME_PLZ = 16383;

  { Largest compressed frame we are willing to inflate. }
  BINK_MAX_INFLATED = 4 * 1024 * 1024;

type

  TBinkFrameType =
  (
    ftData,
    ftCommand
  );

  TBinkFrame = record
    FrameType : TBinkFrameType;
    CommandID : Byte;
    Data      : TBytes;   { command arguments, or file data }
  end;

{ Queues a frame for sending.  Returns False if the frame is empty
  (zero length frames are obsolete and are never sent).  Raises if the
  frame exceeds BINK_MAX_FRAME. }
function SendFrame(
  Sock : TBinkSocket;
  const Frame : TBinkFrame) : Boolean;

{ Non-blocking.  Returns True and fills Frame if a complete frame was
  available in the socket's input buffer (and consumes it).  Returns
  False when more bytes are needed.  Frames with SIZE = 0 are dropped
  silently, as required by the specification.

  Plz = True selects the FTS-1029 header layout; compressed data
  frames are inflated before being returned.  Raises EBinkError if a
  compressed frame is corrupt. }
function ReceiveFrame(
  Sock : TBinkSocket;
  out Frame : TBinkFrame;
  Plz : Boolean = False) : Boolean;

function SendCommand(
  Sock : TBinkSocket;
  Cmd  : Byte;
  const Args : String) : Boolean;

function SendDataFrame(
  Sock : TBinkSocket;
  const Buffer;
  Size : Integer) : Boolean;

{ In PLZ mode (Plz = True) the block is deflated when that makes it
  smaller, and Size must not exceed BINK_MAX_FRAME_PLZ.  Wire is the
  number of payload bytes actually queued. }
function SendDataFrame(
  Sock : TBinkSocket;
  const Buffer;
  Size : Integer;
  Plz : Boolean;
  out Wire : Integer) : Boolean;

{ Command arguments as a string; a trailing NUL terminator is
  stripped (section 4: arguments may be null terminated). }
function FrameDataAsString(
  const Frame : TBinkFrame) : String;

implementation

uses
  zbase,
  zcompres,
  zuncompr;

{ Queues header + payload.  Compressed marks a deflated data frame
  (PLZ). }
function PutFrame(
  Sock : TBinkSocket;
  IsCmd : Boolean;
  CmdID : Byte;
  const Data : TBytes;
  Compressed : Boolean) : Boolean;
var
  Payload : Integer;
  Header  : Word;
  Buf     : TBytes;
  P       : Integer;
begin
  Result := False;

  Payload := Length(Data);

  if IsCmd then
    Inc(Payload);

  if Payload = 0 then
    Exit;

  if Payload > BINK_MAX_FRAME then
    raise EBinkError.Create('Frame exceeds maximum size');

  Header := Payload;

  if IsCmd then
    Header := Header or $8000;

  if Compressed then
    Header := Header or $4000;

  { header + payload sent as one write so a frame is never split
    across separately queued buffers }
  SetLength(Buf, 2 + Payload);
  Buf[0] := Header shr 8;
  Buf[1] := Header and $FF;

  P := 2;

  if IsCmd then
  begin
    Buf[P] := CmdID;
    Inc(P);
  end;

  if Length(Data) > 0 then
    Move(Data[0], Buf[P], Length(Data));

  Sock.Send(Buf[0], Length(Buf));

  Result := True;
end;

function SendFrame(
  Sock : TBinkSocket;
  const Frame : TBinkFrame) : Boolean;
begin
  Result := PutFrame(
    Sock,
    Frame.FrameType = ftCommand,
    Frame.CommandID,
    Frame.Data,
    False);
end;

function Inflate(
  const Src : TBytes;
  out Dst : TBytes) : Boolean;
var
  Cap, Len : LongWord;
  R : Integer;
begin
  Result := False;
  Cap := 65536;

  repeat
    SetLength(Dst, Cap);
    Len := Cap;
    R := uncompress(@Dst[0], Len, Src, Length(Src));

    if R = 0 then
    begin
      SetLength(Dst, Len);
      Exit(True);
    end;

    if R <> -5 then   { anything but Z_BUF_ERROR: corrupt data }
      Exit;

    Cap := Cap * 2;
  until Cap > BINK_MAX_INFLATED;
end;

function ReceiveFrame(
  Sock : TBinkSocket;
  out Frame : TBinkFrame;
  Plz : Boolean = False) : Boolean;
var
  H    : array[0..1] of Byte;
  Size : Integer;
  IsCmd: Boolean;
  Comp : Boolean;
  Body, Raw : TBytes;
begin
  Result := False;

  Frame.FrameType := ftData;
  Frame.CommandID := 0;
  SetLength(Frame.Data, 0);

  while True do
  begin
    if not Sock.CopyIn(0, H, 2) then
      Exit;

    IsCmd := (H[0] and $80) <> 0;

    if Plz then
    begin
      Comp := (not IsCmd) and ((H[0] and $40) <> 0);
      Size := ((H[0] and $3F) shl 8) or H[1];
    end
    else
    begin
      Comp := False;
      Size := ((H[0] and $7F) shl 8) or H[1];
    end;

    if Size = 0 then
    begin
      { obsolete empty frame: silently dropped }
      Sock.Consume(2);
      Continue;
    end;

    if Sock.Available < 2 + Size then
      Exit;

    SetLength(Body, Size);
    Sock.CopyIn(2, Body[0], Size);
    Sock.Consume(2 + Size);

    if IsCmd then
    begin
      Frame.FrameType := ftCommand;
      Frame.CommandID := Body[0];
      SetLength(Frame.Data, Size - 1);

      if Size > 1 then
        Move(Body[1], Frame.Data[0], Size - 1);
    end
    else if Comp then
    begin
      if not Inflate(Body, Raw) then
        raise EBinkError.Create('Corrupt compressed data frame');

      Frame.FrameType := ftData;
      Frame.Data := Raw;
    end
    else
    begin
      Frame.FrameType := ftData;
      Frame.Data := Body;
    end;

    Exit(True);
  end;
end;

function SendCommand(
  Sock : TBinkSocket;
  Cmd  : Byte;
  const Args : String) : Boolean;
var
  D : TBytes;
begin
  SetLength(D, Length(Args));

  if Length(Args) > 0 then
    Move(Args[1], D[0], Length(Args));

  Result := PutFrame(Sock, True, Cmd, D, False);
end;

function SendDataFrame(
  Sock : TBinkSocket;
  const Buffer;
  Size : Integer) : Boolean;
var
  W : Integer;
begin
  Result := SendDataFrame(Sock, Buffer, Size, False, W);
end;

function SendDataFrame(
  Sock : TBinkSocket;
  const Buffer;
  Size : Integer;
  Plz : Boolean;
  out Wire : Integer) : Boolean;
var
  Src, ZBuf : TBytes;
  ZLen   : LongWord;
begin
  Wire := 0;

  if Size <= 0 then
    Exit(False);

  SetLength(Src, Size);
  Move(Buffer, Src[0], Size);

  if Plz then
  begin
    if Size > BINK_MAX_FRAME_PLZ then
      raise EBinkError.Create('Data frame too large for PLZ mode');

    SetLength(ZBuf, Size + Size div 100 + 64);
    ZLen := Length(ZBuf);

    { only worth sending deflated if it is actually smaller }
    if (compress2(@ZBuf[0], ZLen, Src, Size, 6) = 0) and
       (Integer(ZLen) < Size) then
    begin
      SetLength(ZBuf, ZLen);
      Wire := ZLen;
      Exit(PutFrame(Sock, False, 0, ZBuf, True));
    end;
  end;

  Wire := Size;
  Result := PutFrame(Sock, False, 0, Src, False);
end;

function FrameDataAsString(
  const Frame : TBinkFrame) : String;
var
  N : Integer;
begin
  N := Length(Frame.Data);

  while (N > 0) and (Frame.Data[N - 1] = 0) do
    Dec(N);

  if N = 0 then
    Exit('');

  SetLength(Result, N);
  Move(Frame.Data[0], Result[1], N);
end;

end.
