unit BinkQueue;

{$mode objfpc}{$H+}

interface

uses
  Classes,
  SysUtils,
  BinkTransfer;

type

  TBinkQueueCommand =
  (
    bqcUnknown,
    bqcGET,
    bqcGOT,
    bqcSKIP
  );

  TBinkQueueItem = class
  public
    Command  : TBinkQueueCommand;

    FileName : String;
    FileSize : Int64;
    UnixTime : Int64;
    Offset   : Int64;
  end;

  TBinkCommandQueue = class
  private
    FItems : TFPList;

    function GetCount : Integer;
    function GetItem(
      Index : Integer)
      : TBinkQueueItem;

  public
    constructor Create;
    destructor Destroy; override;

    procedure Push(
      Item : TBinkQueueItem);

    function Pop
      : TBinkQueueItem;

    function Peek
      : TBinkQueueItem;

    procedure Clear;

    property Count : Integer
      read GetCount;

    property Items[Index : Integer]
      : TBinkQueueItem
      read GetItem;
  end;

  TBinkKnownFiles = class
  private
    FFiles : TBinkTransferManager;

  public
    constructor Create;
    destructor Destroy; override;

    function AddTransfer
      : TBinkTransfer;

    function Find(
      const FileName : String;
      FileSize : Int64;
      UnixTime : Int64)
      : TBinkTransfer;

    procedure Remove(
      Transfer : TBinkTransfer);

    procedure Clear;

    property Files : TBinkTransferManager
      read FFiles;
  end;

  TBinkPendingFiles = class
  private
    FFiles : TBinkTransferManager;

  public
    constructor Create;
    destructor Destroy; override;

    function AddTransfer
      : TBinkTransfer;

    function Find(
      const FileName : String;
      FileSize : Int64;
      UnixTime : Int64)
      : TBinkTransfer;

    procedure Remove(
      Transfer : TBinkTransfer);

    procedure Clear;

    property Files : TBinkTransferManager
      read FFiles;
  end;

implementation

{ ---------------------------------------------------------------- }

constructor TBinkCommandQueue.Create;
begin
  inherited Create;
  FItems := TFPList.Create;
end;

destructor TBinkCommandQueue.Destroy;
begin
  Clear;
  FItems.Free;
  inherited Destroy;
end;

function TBinkCommandQueue.GetCount
  : Integer;
begin
  Result := FItems.Count;
end;

function TBinkCommandQueue.GetItem(
  Index : Integer)
  : TBinkQueueItem;
begin
  Result :=
    TBinkQueueItem(
      FItems[Index]);
end;

procedure TBinkCommandQueue.Push(
  Item : TBinkQueueItem);
begin
  FItems.Add(Item);
end;

function TBinkCommandQueue.Pop
  : TBinkQueueItem;
begin

  Result := nil;

  if FItems.Count = 0 then
    Exit;

  Result :=
    TBinkQueueItem(
      FItems[0]);

  FItems.Delete(0);
end;

function TBinkCommandQueue.Peek
  : TBinkQueueItem;
begin

  Result := nil;

  if FItems.Count = 0 then
    Exit;

  Result :=
    TBinkQueueItem(
      FItems[0]);
end;

procedure TBinkCommandQueue.Clear;
var
  I : Integer;
begin

  for I :=
    FItems.Count - 1 downto 0 do
    TObject(FItems[I]).Free;

  FItems.Clear;
end;

{ ---------------------------------------------------------------- }

constructor TBinkKnownFiles.Create;
begin
  inherited Create;
  FFiles := TBinkTransferManager.Create;
end;

destructor TBinkKnownFiles.Destroy;
begin
  FFiles.Free;
  inherited Destroy;
end;

function TBinkKnownFiles.AddTransfer
  : TBinkTransfer;
begin
  Result := FFiles.Add;
end;

function TBinkKnownFiles.Find(
  const FileName : String;
  FileSize : Int64;
  UnixTime : Int64)
  : TBinkTransfer;
begin
  Result :=
    FFiles.Find(
      FileName,
      FileSize,
      UnixTime);
end;

procedure TBinkKnownFiles.Remove(
  Transfer : TBinkTransfer);
begin
  FFiles.Remove(
    Transfer);
end;

procedure TBinkKnownFiles.Clear;
begin
  FFiles.Clear;
end;

{ ---------------------------------------------------------------- }

constructor TBinkPendingFiles.Create;
begin
  inherited Create;
  FFiles := TBinkTransferManager.Create;
end;

destructor TBinkPendingFiles.Destroy;
begin
  FFiles.Free;
  inherited Destroy;
end;

function TBinkPendingFiles.AddTransfer
  : TBinkTransfer;
begin
  Result := FFiles.Add;
end;

function TBinkPendingFiles.Find(
  const FileName : String;
  FileSize : Int64;
  UnixTime : Int64)
  : TBinkTransfer;
begin

  Result :=
    FFiles.Find(
      FileName,
      FileSize,
      UnixTime);
end;

procedure TBinkPendingFiles.Remove(
  Transfer : TBinkTransfer);
begin
  FFiles.Remove(
    Transfer);
end;

procedure TBinkPendingFiles.Clear;
begin
  FFiles.Clear;
end;

end.