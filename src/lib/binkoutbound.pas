unit BinkOutbound;

{$mode objfpc}{$H+}

{ The list of files waiting to be sent to a remote system.

  Each entry is a TBinkOutItem that knows what to do once the remote
  has acknowledged it (M_GOT):

    oaMove     flat directory mode: move into a "sent" sub directory
               (or delete it when KillSent is set)
    oaDelete   delete the file          (BSO flow line "^file", packets)
    oaTruncate truncate it to 0 bytes   (BSO flow line "#file")
    oaKeep     leave the file alone     (BSO flow line "file")

  and, for entries that came from a BSO flow file, the line in that
  flow file is marked as sent ("~") and the flow file is deleted when
  every line is done. }

interface

uses
  Classes;

type
  TBinkOutAction = (oaMove, oaDelete, oaTruncate, oaKeep);

  TBinkOutbound = class;
  TBinkOutItem  = class;

  TBinkItemSent = procedure(Item : TBinkOutItem) of object;

  TBinkOutItem = class
  public
    LocalPath : String;   { file on disk }
    WireName  : String;   { name announced to the remote }
    Action    : TBinkOutAction;
    FlowFile  : String;   { BSO flow file this came from, or '' }
    FlowLine  : String;   { the original (trimmed) line in FlowFile }
    Owner     : TBinkOutbound;
    OnSent    : TBinkItemSent; { called after MarkSent did its work }
    Ref       : TObject;       { for the spool that made the item }
  end;

  TBinkOutbound = class
  private
    FItems    : TFPList;
    FKillSent : Boolean;
    FNotes    : TStringList;

    function  GetCount : Integer;
    function  GetItem(Index : Integer) : TBinkOutItem;
    procedure MarkFlowLine(Item : TBinkOutItem);

  public
    constructor Create;
    destructor Destroy; override;

    procedure Clear;

    function AddItem(
      const APath, AWireName : String;
      AAction : TBinkOutAction;
      const AFlowFile : String = '';
      const AFlowLine : String = '') : TBinkOutItem;

    { Replaces the list with the files in Path (top level only). }
    procedure Scan(const Path : String);

    { Appends the files in Path (a missing directory is not an error). }
    procedure AddDir(const Path : String);

    { Called once the remote has acknowledged Item. }
    procedure MarkSent(Item : TBinkOutItem);

    property Count : Integer read GetCount;
    property Items[Index : Integer] : TBinkOutItem read GetItem;

    { Problems a spool met while collecting (an item it had to skip); the
      session logs them.  Cleared by Clear. }
    property Notes : TStringList read FNotes;

    property KillSent : Boolean
      read FKillSent
      write FKillSent;
  end;

const
  BINK_SENT_DIR = 'sent';

implementation

uses
  SysUtils,
  BinkUtil;

constructor TBinkOutbound.Create;
begin
  inherited Create;
  FItems := TFPList.Create;
  FNotes := TStringList.Create;
  FKillSent := False;
end;

destructor TBinkOutbound.Destroy;
begin
  Clear;
  FItems.Free;
  FNotes.Free;
  inherited Destroy;
end;

function TBinkOutbound.GetCount : Integer;
begin
  Result := FItems.Count;
end;

function TBinkOutbound.GetItem(Index : Integer) : TBinkOutItem;
begin
  Result := TBinkOutItem(FItems[Index]);
end;

procedure TBinkOutbound.Clear;
var
  I : Integer;
begin
  for I := FItems.Count - 1 downto 0 do
    TObject(FItems[I]).Free;

  FItems.Clear;
  FNotes.Clear;
end;

function TBinkOutbound.AddItem(
  const APath, AWireName : String;
  AAction : TBinkOutAction;
  const AFlowFile : String;
  const AFlowLine : String) : TBinkOutItem;
begin
  Result := TBinkOutItem.Create;
  Result.LocalPath := APath;
  Result.WireName  := AWireName;
  Result.Action    := AAction;
  Result.FlowFile  := AFlowFile;
  Result.FlowLine  := AFlowLine;
  Result.Owner     := Self;

  FItems.Add(Result);
end;

procedure TBinkOutbound.Scan(const Path : String);
begin
  Clear;
  AddDir(Path);
end;

procedure TBinkOutbound.AddDir(const Path : String);
var
  SR    : TSearchRec;
  Base  : String;
  Found : TStringList;
  I     : Integer;
begin
  Base := IncludeTrailingPathDelimiter(Path);

  Found := TStringList.Create;
  try
    if FindFirst(Base + '*', faAnyFile, SR) = 0 then
    begin
      repeat
        if (SR.Attr and faDirectory) = 0 then
          Found.Add(SR.Name);
      until FindNext(SR) <> 0;

      FindClose(SR);
    end;

    Found.Sort;

    for I := 0 to Found.Count - 1 do
      AddItem(Base + Found[I], Found[I], oaMove);
  finally
    Found.Free;
  end;
end;

{ Marks the line of a flow file that produced Item as sent ("~"), and
  removes the flow file once nothing is left to send. }
procedure TBinkOutbound.MarkFlowLine(Item : TBinkOutItem);
var
  SL   : TStringList;
  I    : Integer;
  L    : String;
  Done : Boolean;
  Tmp  : String;
begin
  if not FileExists(Item.FlowFile) then
    Exit;

  SL := TStringList.Create;
  try
    SL.LoadFromFile(Item.FlowFile);

    for I := 0 to SL.Count - 1 do
    begin
      L := Trim(SL[I]);

      if L = Item.FlowLine then
      begin
        if (L <> '') and (L[1] in ['^', '#', '~', '@']) then
          Delete(L, 1, 1);

        SL[I] := '~' + Trim(L);
        Break;
      end;
    end;

    Done := True;

    for I := 0 to SL.Count - 1 do
    begin
      L := Trim(SL[I]);

      if (L <> '') and (L[1] <> '~') then
        Done := False;
    end;

    if Done then
      DeleteFile(Item.FlowFile)
    else
    begin
      { write to a temporary file and rename, so a crash never leaves
        a half written flow file }
      Tmp := Item.FlowFile + '.tmp';
      SL.SaveToFile(Tmp);

      if not RenameFile(Tmp, Item.FlowFile) then
      begin
        DeleteFile(Item.FlowFile);
        RenameFile(Tmp, Item.FlowFile);
      end;
    end;
  finally
    SL.Free;
  end;
end;

procedure TBinkOutbound.MarkSent(Item : TBinkOutItem);
var
  Dir, Dest : String;
  FS : TFileStream;
begin
  if Item = nil then
    Exit;

  if FileExists(Item.LocalPath) then
  begin
    case Item.Action of

      oaMove :
        if FKillSent then
          DeleteFile(Item.LocalPath)
        else
        begin
          Dir := ExtractFilePath(Item.LocalPath) + BINK_SENT_DIR;
          ForceDirectories(Dir);

          Dest := UniqueFileName(
            IncludeTrailingPathDelimiter(Dir) +
            ExtractFileName(Item.LocalPath));

          RenameFile(Item.LocalPath, Dest);
        end;

      oaDelete :
        DeleteFile(Item.LocalPath);

      oaTruncate :
        try
          FS := TFileStream.Create(Item.LocalPath, fmOpenWrite);
          try
            FS.Size := 0;
          finally
            FS.Free;
          end;
        except
          { leave it; the flow line is still marked }
        end;

      oaKeep : ;
    end;
  end;

  if Item.FlowFile <> '' then
    MarkFlowLine(Item);

  if Assigned(Item.OnSent) then
    Item.OnSent(Item);
end;

end.
