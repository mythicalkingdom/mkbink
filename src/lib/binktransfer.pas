{ SPDX-License-Identifier: GPL-3.0-or-later }
unit BinkTransfer;

{$mode objfpc}{$H+}

interface

uses
  Classes,
  SysUtils;

type

  TBinkTransferState =
  (
    btsIdle,
    btsOffered,
    btsRequested,
    btsTransferring,
    btsPendingAck,
    btsCompleted,
    btsSkipped,
    btsFailed
  );

  TBinkTransferDirection =
  (
    btdSend,
    btdReceive
  );

  TBinkTransfer = class
  private
    FFileName   : String;   { name on the wire (unescaped) }
    FLocalPath  : String;   { file on disk: source or .part file }
    FFileSize   : Int64;
    FUnixTime   : Int64;

    FOffset     : Int64;
    FPosition   : Int64;

    FDirection  : TBinkTransferDirection;
    FState      : TBinkTransferState;

    FPending    : Boolean;
    FActive     : Boolean;

    FStream     : TFileStream;
    FOutItem    : TObject;   { TBinkOutItem this file came from }

  public
    constructor Create;
    destructor Destroy; override;

    procedure OpenForSend;
    procedure OpenForReceive;

    procedure Close;

    function Remaining : Int64;
    function Complete : Boolean;

    property FileName : String
      read FFileName
      write FFileName;

    property LocalPath : String
      read FLocalPath
      write FLocalPath;

    property FileSize : Int64
      read FFileSize
      write FFileSize;

    property UnixTime : Int64
      read FUnixTime
      write FUnixTime;

    property Offset : Int64
      read FOffset
      write FOffset;

    property Position : Int64
      read FPosition
      write FPosition;

    property Direction : TBinkTransferDirection
      read FDirection
      write FDirection;

    property State : TBinkTransferState
      read FState
      write FState;

    property Pending : Boolean
      read FPending
      write FPending;

    property Active : Boolean
      read FActive
      write FActive;

    property Stream : TFileStream
      read FStream;

    property OutItem : TObject
      read FOutItem
      write FOutItem;
  end;

  TBinkTransferManager = class
  private
    FList : TFPList;

    function GetCount : Integer;
    function GetItem(Index : Integer)
      : TBinkTransfer;

  public
    constructor Create;
    destructor Destroy; override;

    function Add : TBinkTransfer;

    function Find(
      const FileName : String;
      FileSize : Int64;
      UnixTime : Int64)
      : TBinkTransfer;

    function FindByName(
      const FileName : String)
      : TBinkTransfer;

    procedure Remove(
      Transfer : TBinkTransfer);

    procedure Clear;

    property Count : Integer
      read GetCount;

    property Items[Index : Integer]
      : TBinkTransfer
      read GetItem;
  end;

implementation

constructor TBinkTransfer.Create;
begin
  inherited Create;

  FFileName := '';
  FLocalPath := '';
  FFileSize := 0;
  FUnixTime := 0;

  FOffset   := 0;
  FPosition := 0;

  FPending := False;
  FActive  := False;

  FState := btsIdle;

  FStream := nil;
end;

destructor TBinkTransfer.Destroy;
begin
  Close;
  inherited Destroy;
end;

procedure TBinkTransfer.Close;
begin
  if Assigned(FStream) then
  begin
    FStream.Free;
    FStream := nil;
  end;
end;

procedure TBinkTransfer.OpenForSend;
begin
  Close;

  if FLocalPath = '' then
    FLocalPath := FFileName;

  FStream :=
    TFileStream.Create(
      FLocalPath,
      fmOpenRead or fmShareDenyNone);

  FFileSize := FStream.Size;

  if FOffset > FFileSize then
    FOffset := FFileSize;

  FStream.Position := FOffset;
  FPosition := FOffset;

  FActive := True;
  FState := btsTransferring;
end;

procedure TBinkTransfer.OpenForReceive;
begin
  Close;

  if FLocalPath = '' then
    FLocalPath := FFileName;

  ForceDirectories(
    ExtractFileDir(ExpandFileName(FLocalPath)));

  if (FOffset > 0) and FileExists(FLocalPath) then
  begin
    { resume: keep the first FOffset bytes of the partial file }
    FStream :=
      TFileStream.Create(
        FLocalPath,
        fmOpenReadWrite or fmShareDenyWrite);

    if FStream.Size < FOffset then
    begin
      FOffset := FStream.Size;
    end;

    FStream.Size := FOffset;
    FStream.Position := FOffset;
    FPosition := FOffset;
  end
  else
  begin
    FOffset := 0;

    FStream :=
      TFileStream.Create(
        FLocalPath,
        fmCreate);

    FPosition := 0;
  end;

  FActive := True;
  FState := btsTransferring;
end;

function TBinkTransfer.Remaining : Int64;
begin
  Result := FFileSize - FPosition;

  if Result < 0 then
    Result := 0;
end;

function TBinkTransfer.Complete : Boolean;
begin
  Result := FPosition >= FFileSize;
end;

constructor TBinkTransferManager.Create;
begin
  inherited Create;
  FList := TFPList.Create;
end;

destructor TBinkTransferManager.Destroy;
begin
  Clear;
  FList.Free;
  inherited Destroy;
end;

function TBinkTransferManager.GetCount
  : Integer;
begin
  Result := FList.Count;
end;

function TBinkTransferManager.GetItem(
  Index : Integer)
  : TBinkTransfer;
begin
  Result :=
    TBinkTransfer(FList[Index]);
end;

function TBinkTransferManager.Add
  : TBinkTransfer;
begin
  Result := TBinkTransfer.Create;
  FList.Add(Result);
end;

function TBinkTransferManager.Find(
  const FileName : String;
  FileSize : Int64;
  UnixTime : Int64)
  : TBinkTransfer;
var
  I : Integer;
begin
  Result := nil;

  for I := 0 to Count - 1 do
  begin
    if CompareText(
         Items[I].FileName,
         FileName) = 0 then
    begin
      if (Items[I].FileSize = FileSize)
      and (Items[I].UnixTime = UnixTime) then
      begin
        Result := Items[I];
        Exit;
      end;
    end;
  end;
end;

function TBinkTransferManager.FindByName(
  const FileName : String)
  : TBinkTransfer;
var
  I : Integer;
begin
  Result := nil;

  for I := 0 to Count - 1 do
  begin
    if CompareText(
         Items[I].FileName,
         FileName) = 0 then
    begin
      Result := Items[I];
      Exit;
    end;
  end;
end;

procedure TBinkTransferManager.Remove(
  Transfer : TBinkTransfer);
begin
  if Transfer = nil then
    Exit;

  FList.Remove(Transfer);
  Transfer.Free;
end;

procedure TBinkTransferManager.Clear;
var
  I : Integer;
begin
  for I := FList.Count - 1 downto 0 do
    TObject(FList[I]).Free;

  FList.Clear;
end;

end.