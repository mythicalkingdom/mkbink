unit BinkAttach;

{$mode objfpc}{$H+}

{ FrontDoor style ("attach style") outbound.

  Instead of flow files, outbound mail lives in a netmail directory of
  stored messages (1.msg, 2.msg, ... in the FTS-0001 format) that the
  BBS, a tosser or a person writes.  Two options say where things are:

    netmail directory   the *.msg files
    attach directory    where attached files and the temporary packets
                        live (see below)

  A message is sent to a link when its destination is that link and it
  is not marked Sent.  Two kinds:

    file attach   the message has the File Attach flag; its subject
                  names the file.  Only the FILE is sent (the message
                  is just the instruction).  A leading ^ in the subject
                  deletes the file after it was sent, # truncates it.
                  A bare file name is looked up in <attach>/<link>/ and
                  then in <attach>/.
    netmail       every other message for the link is written into one
                  packet (<hex>.pkt, built in <attach>/packets/<link>/)
                  and the packet is sent.

  Order: Crash messages first, then normal ones, then Hold ones (Hold for
  pickup flag), which are only sent when the remote called us.  Direct and
  immediate flavours do not exist here.  When a file or packet was acknowledged by
  the remote, the message is marked Sent, or deleted if it has Kill/Sent.
  File requests (File Request flag) are not supported and stay untouched.

  <link> is zone.net.node.point, e.g. 1.110.100.0.

  The message files are read and updated with the MKMsg units of the MK
  BBS (MKMsgFid), which must be on the unit path (see the Makefile).
  Those units are not thread safe, so all use of them is serialised
  here. }

interface

uses
  Classes,
  SysUtils,
  SyncObjs,
  BinkTypes,
  BinkNode,
  BinkOutbound,
  BinkSpool;

type
  TAttachJob = class
  public
    Addr : TFTNAddress;
    Msgs : array of LongInt;
  end;

  TBinkAttachSpool = class(TBinkSpool)
  private
    FNetmail : String;
    FAttach  : String;
    FZone    : Word;
    FOrigin  : TFTNAddress;
    FCS      : TCriticalSection;
    FJobs    : TFPList;           { TAttachJob, until Unlock }
    FLocked  : TStringList;       { links locked by a session of ours }

    function  LinkName(const A : TFTNAddress) : String;
    function  LinkAttachDir(const A : TFTNAddress) : String;
    function  PacketDir(const A : TFTNAddress) : String;
    function  MsgPath(Num : LongInt) : String;
    function  ResolveFile(
      const Subject : String;
      const A : TFTNAddress;
      out Path : String;
      out Act : TBinkOutAction) : Boolean;

    procedure Scan(
      const A : TFTNAddress;
      IncludeHold, Build : Boolean;
      Dest : TBinkOutbound;
      out Count : Integer;
      out Bytes : Int64);

    procedure ItemSent(Item : TBinkOutItem);

  public
    { Origin is our address: the sender of the packets and of the
      messages Attach writes.  DefaultZone is used for messages that
      carry no zone. }
    constructor Create(
      const ANetmail, AAttach : String;
      ADefaultZone : Word;
      const AOrigin : TFTNAddress);
    destructor Destroy; override;

    function  TryLock(const A : TFTNAddress) : Boolean; override;
    procedure Unlock(const A : TFTNAddress); override;

    function Collect(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      Dest : TBinkOutbound) : Integer; override;

    function Pending(
      const A : TFTNAddress;
      IncludeHold : Boolean) : Integer; override;

    function PendingInfo(
      const A : TFTNAddress;
      IncludeHold : Boolean;
      out Bytes : Int64) : Integer; override;

    { Copies FileName into <attach>/<link>/ (moves it for oaDelete) and
      writes a File Attach message for it.  Flavour I/C = crash, D/N =
      normal; H is not supported.  Returns the message's path. }
    function Attach(
      const A : TFTNAddress;
      const FileName : String;
      Flavour : Char;
      Action : TBinkOutAction) : String; override;

    property Netmail : String read FNetmail;
    property AttachDir : String read FAttach;
  end;

implementation

uses
  DateUtils,
  MKGlobT,
  MKMsgAbs,
  MKMsgFid,
  MKMsgPkt,
  BinkUtil;

const
  ATTR_PRIVATE = $0001;
  ATTR_CRASH   = $0002;
  ATTR_ATTACH  = $0010;

type
  TCand = record
    Num    : LongInt;
    Rank   : Integer;       { 0 crash, 1 normal, 2 hold }
    Attach : Boolean;
    Subject : String;
    Size   : Int64;
  end;

var
  GPacketSeq : Integer = 0;

function ToAddr(const A : TFTNAddress) : AddrType;
begin
  Result.Zone  := A.Zone;
  Result.Net   := A.Net;
  Result.Node  := A.Node;
  Result.Point := A.Point;
end;

function FromAddr(const A : AddrType) : TFTNAddress;
begin
  Result := Default(TFTNAddress);
  Result.Zone  := A.Zone;
  Result.Net   := A.Net;
  Result.Node  := A.Node;
  Result.Point := A.Point;
end;

function FileSizeOf(const Path : String) : Int64;
var
  SR : TSearchRec;
begin
  Result := 0;

  if FindFirst(Path, faAnyFile, SR) = 0 then
  begin
    Result := SR.Size;
    FindClose(SR);
  end;
end;

constructor TBinkAttachSpool.Create(
  const ANetmail, AAttach : String;
  ADefaultZone : Word;
  const AOrigin : TFTNAddress);
begin
  inherited Create;
  FNetmail := ExcludeTrailingPathDelimiter(ANetmail);
  FAttach  := ExcludeTrailingPathDelimiter(AAttach);
  FZone    := ADefaultZone;
  FOrigin  := AOrigin;
  FCS      := TCriticalSection.Create;
  FJobs    := TFPList.Create;
  FLocked  := TStringList.Create;
end;

destructor TBinkAttachSpool.Destroy;
var
  I : Integer;
begin
  for I := 0 to FJobs.Count - 1 do
    TObject(FJobs[I]).Free;

  FJobs.Free;
  FLocked.Free;
  FCS.Free;
  inherited Destroy;
end;

function TBinkAttachSpool.LinkName(const A : TFTNAddress) : String;
begin
  Result := AddressToDirName(A);
end;

function TBinkAttachSpool.LinkAttachDir(const A : TFTNAddress) : String;
begin
  Result := FAttach + PathDelim + LinkName(A);
end;

function TBinkAttachSpool.PacketDir(const A : TFTNAddress) : String;
begin
  Result := FAttach + PathDelim + 'packets' + PathDelim + LinkName(A);
end;

function TBinkAttachSpool.MsgPath(Num : LongInt) : String;
begin
  Result := FNetmail + PathDelim + IntToStr(Num) + '.msg';
end;

{ ------------------------------------------------------------------ }
{ Locking                                                             }
{ ------------------------------------------------------------------ }

function TBinkAttachSpool.TryLock(const A : TFTNAddress) : Boolean;
var
  Key : String;
begin
  Key := LinkName(A);
  Result := False;

  FCS.Enter;
  try
    if FLocked.IndexOf(Key) >= 0 then
      Exit;

    if not ForceDirectories(FAttach) then
      raise EBinkError.CreateFmt(
        'Cannot create the attach directory %s', [FAttach]);

    if TryLockFile(FAttach + PathDelim + Key + '.bsy') then
    begin
      FLocked.Add(Key);
      Result := True;
    end;
  finally
    FCS.Leave;
  end;
end;

procedure TBinkAttachSpool.Unlock(const A : TFTNAddress);
var
  Key : String;
  I   : Integer;
  Job : TAttachJob;
begin
  Key := LinkName(A);

  FCS.Enter;
  try
    for I := FJobs.Count - 1 downto 0 do
    begin
      Job := TAttachJob(FJobs[I]);

      if SameAddress(Job.Addr, A) then
      begin
        Job.Free;
        FJobs.Delete(I);
      end;
    end;

    I := FLocked.IndexOf(Key);

    if I >= 0 then
    begin
      FLocked.Delete(I);
      DeleteFile(FAttach + PathDelim + Key + '.bsy');
    end;
  finally
    FCS.Leave;
  end;
end;

{ ------------------------------------------------------------------ }
{ Finding the mail                                                    }
{ ------------------------------------------------------------------ }

{ The subject of a File Attach message: [^|#]file.  DOS style
  separators are accepted. }
function TBinkAttachSpool.ResolveFile(
  const Subject : String;
  const A : TFTNAddress;
  out Path : String;
  out Act : TBinkOutAction) : Boolean;
var
  S : String;
begin
  Result := False;
  Act := oaKeep;
  S := Trim(Subject);

  if S = '' then
    Exit;

  case S[1] of
    '^' : begin Act := oaDelete;   S := Trim(Copy(S, 2, MaxInt)); end;
    '#' : begin Act := oaTruncate; S := Trim(Copy(S, 2, MaxInt)); end;
  end;

  if S = '' then
    Exit;

  S := StringReplace(S, '\', '/', [rfReplaceAll]);

  if (S[1] = '/') or (Pos('/', S) > 0) then
    Path := S
  else if FileExists(LinkAttachDir(A) + PathDelim + S) then
    Path := LinkAttachDir(A) + PathDelim + S
  else
    Path := FAttach + PathDelim + S;

  Result := FileExists(Path);
end;

procedure TBinkAttachSpool.Scan(
  const A : TFTNAddress;
  IncludeHold, Build : Boolean;
  Dest : TBinkOutbound;
  out Count : Integer;
  out Bytes : Int64);
var
  M     : FidoMsgObj;
  Cands : array of TCand;
  NC, I, J, Flav : Integer;
  Dst   : AddrType;
  Attr  : Word;
  Path, Name : String;
  Act   : TBinkOutAction;
  Item  : TBinkOutItem;
  Job   : TAttachJob;
  P     : PktMsgObj;
  PA, PD : AddrType;
  Res   : Word;
  PktPath, FromName, ToName : String;
  C     : Char;
  Org   : AddrType;
  SR    : TSearchRec;
  NonAttach : Integer;
begin
  Count := 0;
  Bytes := 0;
  NC := 0;

  if not DirectoryExists(FNetmail) then
    Exit;

  FCS.Enter;
  try
    M.Init;
    try
      M.SetMsgPath(FNetmail);
      M.SetDefaultZone(FZone);
      M.SetMailType(mmtNetMail);

      if M.OpenMsgBase <> 0 then
        Exit;

      { pass 1: which messages are for this link }
      M.SeekFirst(1);

      while M.SeekFound do
      begin
        M.MsgStartUp;
        M.GetDest(Dst);
        Attr := M.BufferWord(186);

        if SameAddress(FromAddr(Dst), A) and
           (not M.IsSent) and
           (not M.IsFileReq) and
           (not M.IsDeleted) and
           (IncludeHold or (not M.IsHold)) then
        begin
          SetLength(Cands, NC + 1);
          Cands[NC].Num     := M.GetMsgNum;
          if M.IsHold then
            Cands[NC].Rank := 2
          else if M.IsCrash then
            Cands[NC].Rank := 0
          else
            Cands[NC].Rank := 1;

          Cands[NC].Attach  := M.IsFAttach;
          Cands[NC].Subject := Trim(M.GetSubj);
          Cands[NC].Size    := FileSizeOf(MsgPath(M.GetMsgNum));
          Inc(NC);
        end;

        M.SeekNext;
      end;

      { packets an earlier, interrupted session left behind (we hold the
        link's lock, so they are not in use) }
      if Build then
      begin
        if FindFirst(PacketDir(A) + PathDelim + '*.pkt', faAnyFile, SR) = 0 then
        begin
          repeat
            DeleteFile(PacketDir(A) + PathDelim + SR.Name);
          until FindNext(SR) <> 0;

          FindClose(SR);
        end;
      end;

      { pass 2: crash first, then normal; files before the packet }
      for Flav := 0 to 2 do
      begin
        NonAttach := 0;

        for I := 0 to NC - 1 do
        begin
          if Cands[I].Rank <> Flav then
            Continue;

          if Cands[I].Attach then
          begin
            if not ResolveFile(Cands[I].Subject, A, Path, Act) then
              Continue;

            Inc(Count);
            Inc(Bytes, FileSizeOf(Path));

            if Build then
            begin
              Item := Dest.AddItem(Path, ExtractFileName(Path), Act);
              Job  := TAttachJob.Create;
              Job.Addr := A;
              SetLength(Job.Msgs, 1);
              Job.Msgs[0] := Cands[I].Num;
              FJobs.Add(Job);
              Item.Ref := Job;
              Item.OnSent := @ItemSent;
            end;
          end
          else
          begin
            Inc(NonAttach);
            Inc(Bytes, Cands[I].Size);
          end;
        end;

        if NonAttach = 0 then
          Continue;

        Inc(Count);       { one packet }

        if not Build then
          Continue;

        ForceDirectories(PacketDir(A));

        Name := LowerCase(IntToHex(
          Cardinal(DateTimeToUnix(Now)) +
          Cardinal(InterlockedIncrement(GPacketSeq)), 8)) + '.pkt';
        PktPath := PacketDir(A) + PathDelim + Name;

        Job := TAttachJob.Create;
        Job.Addr := A;
        PA := ToAddr(FOrigin);
        PD := ToAddr(A);
        P.Init;
        try
          P.SetMsgPath(PktPath);
          P.SetMailType(mmtNetMail);
          P.SetPacketInfo(PA, PD, '');

          for I := 0 to NC - 1 do
          begin
            if (Cands[I].Rank <> Flav) or Cands[I].Attach then
              Continue;

            M.SetMsgLoc(Cands[I].Num);
            M.MsgStartUp;
            M.GetOrig(Org);
            M.GetDest(Dst);
            Attr := M.BufferWord(186);
            FromName := M.GetFrom;
            ToName := M.GetTo;

            { the packet unit insists on a sender and a recipient }
            if FromName = '' then
              FromName := 'Unknown';

            if ToName = '' then
              ToName := 'Sysop';

            P.StartNewMsg;
            P.SetFrom(FromName);
            P.SetTo(ToName);
            P.SetSubj(M.GetSubj);
            P.SetDest(Dst);
            P.SetOrig(Org);
            P.SetCost(M.GetCost);
            P.SetDate(M.GetDate);
            P.SetTime(M.GetTime);
            P.SetPriv((Attr and ATTR_PRIVATE) <> 0);
            P.SetCrash((Attr and ATTR_CRASH) <> 0);

            { the text goes over unchanged (kludge lines too; the packet
              unit rebuilds INTL, FMPT and TOPT itself) }
            M.MsgTxtStartUp;

            repeat
              C := M.GetChar;

              if (C = #0) or M.EOM then
                Break;

              P.DoChar(C);
            until False;

            Res := P.WriteMsg;

            if Res <> 0 then
            begin
              Dest.Notes.Add(Format(
                'Netmail %d for %s not packed (MKMsgPkt error %d); it stays in the netmail directory',
                [Cands[I].Num, AddressToString(A), Res]));
              Continue;
            end;

            J := Length(Job.Msgs);
            SetLength(Job.Msgs, J + 1);
            Job.Msgs[J] := Cands[I].Num;
          end;
        finally
          P.Done;
        end;

        if Length(Job.Msgs) = 0 then
        begin
          Job.Free;
          DeleteFile(PktPath);
          Dec(Count);
          Continue;
        end;

        FJobs.Add(Job);
        Item := Dest.AddItem(PktPath, Name, oaDelete);
        Item.Ref := Job;
        Item.OnSent := @ItemSent;
      end;
    finally
      M.Done;
    end;
  finally
    FCS.Leave;
  end;
end;

function TBinkAttachSpool.Collect(
  const A : TFTNAddress;
  IncludeHold : Boolean;
  Dest : TBinkOutbound) : Integer;
var
  Bytes : Int64;
begin
  Scan(A, IncludeHold, True, Dest, Result, Bytes);
end;

function TBinkAttachSpool.Pending(
  const A : TFTNAddress;
  IncludeHold : Boolean) : Integer;
var
  Bytes : Int64;
begin
  Scan(A, IncludeHold, False, nil, Result, Bytes);
end;

function TBinkAttachSpool.PendingInfo(
  const A : TFTNAddress;
  IncludeHold : Boolean;
  out Bytes : Int64) : Integer;
begin
  Scan(A, IncludeHold, False, nil, Result, Bytes);
end;

{ ------------------------------------------------------------------ }
{ After the remote acknowledged a file or packet                      }
{ ------------------------------------------------------------------ }

procedure TBinkAttachSpool.ItemSent(Item : TBinkOutItem);
var
  Job : TAttachJob;
  M   : FidoMsgObj;
  I   : Integer;
begin
  Job := TAttachJob(Item.Ref);

  if Job = nil then
    Exit;

  FCS.Enter;
  try
    M.Init;
    try
      M.SetMsgPath(FNetmail);
      M.SetDefaultZone(FZone);
      M.SetMailType(mmtNetMail);
      M.OpenMsgBase;

      for I := 0 to High(Job.Msgs) do
      begin
        if not FileExists(MsgPath(Job.Msgs[I])) then
          Continue;

        M.SetMsgLoc(Job.Msgs[I]);
        M.MsgStartUp;

        if M.IsKillSent then
          M.DeleteMsg
        else
          M.SetSent(True);
      end;
    finally
      M.Done;
    end;
  finally
    FCS.Leave;
  end;
end;

{ ------------------------------------------------------------------ }
{ Queueing a file                                                     }
{ ------------------------------------------------------------------ }

function TBinkAttachSpool.Attach(
  const A : TFTNAddress;
  const FileName : String;
  Flavour : Char;
  Action : TBinkOutAction) : String;
var
  M : FidoMsgObj;
  Crash, Hold : Boolean;
  Dir, Dest, Prefix : String;
  Dst, Org : AddrType;
  T : TDateTime;
  Y, Mo, D, H, Mi, S, Ms : Word;
  Src : TFileStream;
  Dst2 : TFileStream;
begin
  Flavour := UpCase(Flavour);

  Hold := False;

  case Flavour of
    'I', 'C' : Crash := True;
    'D', 'N' : Crash := False;
    'H'      : begin Crash := False; Hold := True; end;
  else
    raise EBinkError.CreateFmt(
      'Flavour %s is not available in attach style (use C, N or H)',
      [Flavour]);
  end;

  if FOrigin.Zone = 0 then
    raise EBinkError.Create('Attach style needs our own address (-a)');

  if not FileExists(FileName) then
    raise EBinkError.CreateFmt('No such file: %s', [FileName]);

  Dir := LinkAttachDir(A);

  if not ForceDirectories(Dir) then
    raise EBinkError.CreateFmt('Cannot create %s', [Dir]);

  Dest := UniqueFileName(Dir + PathDelim + ExtractFileName(FileName));

  { with kill-after-send the file is moved, otherwise copied }
  if (Action = oaDelete) and RenameFile(FileName, Dest) then
    { moved }
  else
  begin
    Src := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
    try
      Dst2 := TFileStream.Create(Dest, fmCreate);
      try
        Dst2.CopyFrom(Src, 0);
      finally
        Dst2.Free;
      end;
    finally
      Src.Free;
    end;

    if Action = oaDelete then
      DeleteFile(FileName);
  end;

  case Action of
    oaDelete   : Prefix := '^';
    oaTruncate : Prefix := '#';
  else
    Prefix := '';
  end;

  ForceDirectories(FNetmail);
  T := Now;
  DecodeDate(T, Y, Mo, D);
  DecodeTime(T, H, Mi, S, Ms);

  FCS.Enter;
  try
    M.Init;
    try
      M.SetMsgPath(FNetmail);
      M.SetDefaultZone(FZone);
      M.SetMailType(mmtNetMail);
      M.OpenMsgBase;
      M.StartNewMsg;

      Dst := ToAddr(A);
      Org := ToAddr(FOrigin);
      M.SetDest(Dst);
      M.SetOrig(Org);
      M.SetFrom('mkbink');
      M.SetTo('Sysop');
      M.SetSubj(Prefix + ExpandFileName(Dest));
      M.SetDate(Format('%.2d-%.2d-%.2d', [Mo, D, Y mod 100]));
      M.SetTime(Format('%.2d:%.2d', [H, Mi]));
      M.SetLocal(True);
      M.SetPriv(True);
      M.SetFAttach(True);
      M.SetCrash(Crash);
      M.SetHold(Hold);
      M.SetKillSent(Action = oaDelete);
      M.DoStringLn('File attached by mkbink');

      if M.WriteMsg <> 0 then
        raise EBinkError.Create('Cannot write the netmail message');

      Result := MsgPath(M.GetMsgNum);
    finally
      M.Done;
    end;
  finally
    FCS.Leave;
  end;
end;

end.
