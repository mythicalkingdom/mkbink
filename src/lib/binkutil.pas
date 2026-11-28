{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkUtil;

{$mode objfpc}{$H+}

interface

{ Modification time of a file as unix time (UTC seconds), or -1. }
function GetFileUnixTime(const FileName: String): Int64;

{ Sets the modification time of a file from unix time. }
function SetFileUnixTime(const FileName: String;
  UnixTime: Int64): Boolean;

{ Returns FileName if it does not exist, otherwise FileName.1,
  FileName.2, ... (the suffix is simply appended). }
function UniqueFileName(const FileName: String): String;

implementation

uses
  SysUtils,
  {$IFDEF UNIX}
  BaseUnix,
  {$ENDIF}
  DateUtils;

function GetFileUnixTime(const FileName: String): Int64;
{$IFDEF UNIX}
var
  St : Stat;
begin
  if fpStat(FileName, St) <> 0 then
    Exit(-1);

  Result := St.st_mtime;
end;
{$ELSE}
var
  Age : LongInt;
begin
  Age := FileAge(FileName);

  if Age = -1 then
    Exit(-1);

  Result := DateTimeToUnix(FileDateToDateTime(Age));
end;
{$ENDIF}

function SetFileUnixTime(const FileName: String;
  UnixTime: Int64): Boolean;
{$IFDEF UNIX}
var
  T : UTimBuf;
begin
  T.actime  := UnixTime;
  T.modtime := UnixTime;

  Result := fpUtime(PChar(FileName), @T) = 0;
end;
{$ELSE}
begin
  Result :=
    FileSetDate(FileName,
      DateTimeToFileDate(UnixToDateTime(UnixTime))) = 0;
end;
{$ENDIF}

function UniqueFileName(const FileName: String): String;
var
  N : Integer;
begin
  Result := FileName;
  N := 0;

  while FileExists(Result) do
  begin
    Inc(N);
    Result := FileName + '.' + IntToStr(N);
  end;
end;

end.
