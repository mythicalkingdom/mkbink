{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkSpool;

{$mode objfpc}{$H+}

{ What a session needs from an outbound spool, whatever its layout:

    BinkBso     BinkleyTerm style outbound (flow files, packets)
    BinkAttach  FrontDoor style: netmail *.MSG files, some with an
                attached file (needs the MKMsg units, see the Makefile)

  A session locks the link, collects what is queued for it, and each
  collected item tells the spool when it was sent (TBinkOutItem.OnSent
  or the owning TBinkOutbound). }

interface

uses
  BinkTypes,
  BinkOutbound;

type
  TBinkSpool = class
  public
    { Fails if another session (or process) holds the link; a lock left
      by a dead process, or older than 12 hours, is taken over. }
    function  TryLock(const A : TFTNAddress) : Boolean; virtual; abstract;
    procedure Unlock(const A : TFTNAddress); virtual; abstract;

    { Adds everything queued for A to Dest, most urgent first.  Hold is
      only included when IncludeHold is set (they are calling us).
      Returns the number of items added. }
    function Collect(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      Dest : TBinkOutbound) : Integer; virtual; abstract;

    { What Collect would find (nothing is changed or created). }
    function Pending(
      const A : TFTNAddress;
      IncludeHold : Boolean) : Integer; virtual; abstract;

    function PendingInfo(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      out Bytes : Int64) : Integer; virtual; abstract;

    { Queues FileName for A.  Flavour is I, C, D, N or H (a spool may
      not support all).  Returns where it was recorded. }
    function Attach(
      const A : TFTNAddress;
      const FileName : String;
      Flavour : Char;
      Action : TBinkOutAction) : String; virtual; abstract;

    { Adds a file request (FTS-0006) to A: the name (wildcards allowed),
      a password of 6 characters or fewer, or '', and an update request,
      '+' or '-' and a UNIX time in decimal ('+599634000': the files that
      match and are newer; '-599634000': dated up to and including that
      time), or ''.  Returns where it was recorded.  A spool without
      file requests raises EBinkError. }
    function Request(
      const A : TFTNAddress;
      const Name, Password : String;
      const Update : String = '') : String; virtual;

    { Raises EBinkError when Request would refuse these, and writes
      nothing: for checking a whole list before any of it is written. }
    procedure CheckRequest(
      const Name, Password : String;
      const Update : String = ''); virtual;
  end;

{ Creates the lock file Path (holding our pid).  False when it exists
  and is live.  Raises EBinkError when it cannot be created for any
  other reason (a configuration problem, not a busy link). }
function TryLockFile(const Path : String) : Boolean;

implementation

uses
  {$IFDEF UNIX}
  BaseUnix,
  {$ENDIF}
  Classes,
  SysUtils,
  DateUtils,
  BinkUtil;

const
  STALE_LOCK_SECONDS = 12 * 3600;

procedure TBinkSpool.CheckRequest(
  const Name, Password : String;
  const Update : String);
begin
  raise EBinkError.Create('This outbound style has no file requests');
end;

function TBinkSpool.Request(
  const A : TFTNAddress;
  const Name, Password : String;
  const Update : String) : String;
begin
  raise EBinkError.Create('This outbound style has no file requests');
end;

function TryLockFile(const Path : String) : Boolean;
var
  Attempt : Integer;
  {$IFDEF UNIX}
  Fd, Err : cint;
  Pid : String;
  PidNum : LongInt;
  SL : TStringList;
  {$ENDIF}
  Age : Int64;
begin
  Result := False;

  { Only report "busy" when the flag really exists.  A missing or
    unwritable outbound is a configuration problem and is raised. }
  if not ForceDirectories(ExtractFilePath(Path)) then
    raise EBinkError.CreateFmt(
      'Cannot create the outbound directory %s', [ExtractFilePath(Path)]);

  for Attempt := 1 to 2 do
  begin
    {$IFDEF UNIX}
    Fd := fpOpen(Path, O_WRONLY or O_CREAT or O_EXCL, &666);

    if Fd >= 0 then
    begin
      Pid := IntToStr(fpGetPid) + LineEnding;
      fpWrite(Fd, Pid[1], Length(Pid));
      fpClose(Fd);
      Exit(True);
    end;

    Err := fpGetErrno;

    if Err <> ESysEEXIST then
      raise EBinkError.CreateFmt(
        'Cannot create lock file %s: %s', [Path, SysErrorMessage(Err)]);
    {$ELSE}
    if not FileExists(Path) then
    begin
      with TFileStream.Create(Path, fmCreate) do Free;
      Exit(True);
    end;
    {$ENDIF}

    { exists: is it stale? }
    if not FileExists(Path) then
      Continue;

    Age := DateTimeToUnix(Now) - GetFileUnixTime(Path);

    if Age > STALE_LOCK_SECONDS then
    begin
      DeleteFile(Path);
      Continue;
    end;

    {$IFDEF UNIX}
    SL := TStringList.Create;
    try
      try
        SL.LoadFromFile(Path);
        PidNum := StrToIntDef(Trim(SL.Text), 0);
      except
        PidNum := 0;
      end;
    finally
      SL.Free;
    end;

    { owner process is gone: take the flag over }
    if (PidNum > 0) and (fpKill(PidNum, 0) <> 0) and
       (fpGetErrno = ESysESRCH) then
    begin
      DeleteFile(Path);
      Continue;
    end;
    {$ENDIF}

    Exit(False);
  end;
end;

end.
