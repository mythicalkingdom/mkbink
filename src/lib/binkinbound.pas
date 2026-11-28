{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkInbound;

{$mode objfpc}{$H+}

{ Inbound directory handling.

  Incoming files are written to  <name>.<size>.<unixtime>.part  and
  renamed to their real name when complete.  Keeping size and time in
  the partial's name means a partial file is only ever resumed (M_GET
  with an offset) for the very same version of the remote file. }

interface

uses
  Classes,
  SysUtils;

type
  TBinkInbound = class
  private
    FPath : String;

  public
    constructor Create(const APath : String);

    { A name the remote is allowed to make us create: a plain file
      name, no path components, no control characters. }
    class function IsSafeName(const Name : String) : Boolean;

    function PartialPath(
      const Name : String;
      Size, UnixTime : Int64) : String;

    { Size of an existing partial file, or 0. }
    function PartialSize(
      const Name : String;
      Size, UnixTime : Int64) : Int64;

    procedure DiscardPartial(
      const Name : String;
      Size, UnixTime : Int64);

    { True if an identical (name, size, time) file is already in the
      inbound directory. }
    function HasComplete(
      const Name : String;
      Size, UnixTime : Int64) : Boolean;

    { Moves a finished .part file into place and stamps it with the
      remote's timestamp.  If a different file with that name already
      exists a numeric suffix is added.  Returns the final path. }
    function Finalize(
      const PartFile, Name : String;
      UnixTime : Int64) : String;

    { Creates a zero length file; returns the final path. }
    function StoreEmpty(
      const Name : String;
      UnixTime : Int64) : String;

    procedure StoreFile(
      const Name : String;
      const Data : TBytes);

    property Path : String read FPath;
  end;

implementation

uses
  BinkUtil;

constructor TBinkInbound.Create(const APath : String);
begin
  inherited Create;
  FPath := IncludeTrailingPathDelimiter(APath);
end;

class function TBinkInbound.IsSafeName(const Name : String) : Boolean;
var
  I : Integer;
begin
  Result := False;

  if (Name = '') or (Length(Name) > 200) then
    Exit;

  if (Name = '.') or (Name = '..') then
    Exit;

  for I := 1 to Length(Name) do
    if (Name[I] < ' ') or (Name[I] = #127) or
       (Name[I] = '/') or (Name[I] = '\') then
      Exit;

  Result := True;
end;

function TBinkInbound.PartialPath(
  const Name : String;
  Size, UnixTime : Int64) : String;
begin
  Result := FPath + Name + '.' +
    IntToStr(Size) + '.' + IntToStr(UnixTime) + '.part';
end;

function TBinkInbound.PartialSize(
  const Name : String;
  Size, UnixTime : Int64) : Int64;
var
  P  : String;
  SR : TSearchRec;
begin
  Result := 0;
  P := PartialPath(Name, Size, UnixTime);

  if FindFirst(P, faAnyFile, SR) = 0 then
  begin
    Result := SR.Size;
    FindClose(SR);
  end;
end;

procedure TBinkInbound.DiscardPartial(
  const Name : String;
  Size, UnixTime : Int64);
begin
  DeleteFile(PartialPath(Name, Size, UnixTime));
end;

function TBinkInbound.HasComplete(
  const Name : String;
  Size, UnixTime : Int64) : Boolean;
var
  P  : String;
  SR : TSearchRec;
begin
  Result := False;
  P := FPath + Name;

  if FindFirst(P, faAnyFile, SR) = 0 then
  begin
    Result := (SR.Size = Size) and
              (GetFileUnixTime(P) = UnixTime);
    FindClose(SR);
  end;
end;

function TBinkInbound.Finalize(
  const PartFile, Name : String;
  UnixTime : Int64) : String;
begin
  Result := UniqueFileName(FPath + Name);

  if not RenameFile(PartFile, Result) then
    raise EInOutError.CreateFmt(
      'Cannot rename %s to %s', [PartFile, Result]);

  SetFileUnixTime(Result, UnixTime);
end;

function TBinkInbound.StoreEmpty(
  const Name : String;
  UnixTime : Int64) : String;
var
  FS : TFileStream;
begin
  ForceDirectories(FPath);

  Result := UniqueFileName(FPath + Name);

  FS := TFileStream.Create(Result, fmCreate);
  FS.Free;

  SetFileUnixTime(Result, UnixTime);
end;

procedure TBinkInbound.StoreFile(
  const Name : String;
  const Data : TBytes);
var
  FS : TFileStream;
begin
  ForceDirectories(FPath);

  FS := TFileStream.Create(
    FPath + ExtractFileName(Name),
    fmCreate);

  try
    if Length(Data) > 0 then
      FS.WriteBuffer(Data[0], Length(Data));
  finally
    FS.Free;
  end;
end;

end.
