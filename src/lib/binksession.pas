unit BinkSession;

{$mode objfpc}{$H+}

{ A complete binkp/1.0 session (FTS-1026), usable on both sides:

    Originate(Node)  - we connect out to Node  (Tables 1, 3-6)
    Answer(Socket)   - a caller connected to us (Tables 2, 3-6)

  After the session setup stage both sides run the same file transfer
  stage, implemented in Transfer():

    * the Receive routine  (Table 4)  - HandleFrame / StartReceive
    * the Transmit routine (Table 5)  - TxStep
    * ProcessTheQueue      (Table 6)  - ProcessQueue

  The transfer stage is a single threaded loop that multiplexes
  reading and writing through BinkSocket's buffered, non-blocking
  Pump(), so files can be sent and received simultaneously. }

interface

uses
  Classes,
  SysUtils,
  BinkTypes,
  BinkNode,
  BinkSocket,
  BinkFrame,
  BinkProtocol,
  BinkTransfer,
  BinkQueue,
  BinkInbound,
  BinkOutbound,
  BinkSpool,
  BinkBso,
  BinkCram,
  BinkCrypt;

type

  TBinkLogEvent = procedure(const Msg : String) of object;

  { What a session is doing, for displays: copied out of the session by
    the session's own thread (OnProgress), so it is always consistent. }
  TBinkProgress = record
    State         : TBinkState;
    Originating   : Boolean;
    Remote        : String;       { the remote's addresses }
    SysName       : String;       { as the remote told us (M_NUL) }
    Sysop         : String;
    Location      : String;
    Version       : String;
    Secure        : Boolean;
    Plz           : Boolean;
    Nr            : Boolean;
    BytesSent     : Int64;
    BytesReceived : Int64;
    FilesSent     : Integer;
    FilesReceived : Integer;
    TxName        : String;       { file being sent, '' = none }
    TxPos         : Int64;
    TxSize        : Int64;
    RxName        : String;       { file being received }
    RxPos         : Int64;
    RxSize        : Int64;
  end;

  TBinkProgressEvent = procedure(Sender : TObject;
    const P : TBinkProgress) of object;

  { Answering side: decide whether a presented address is known and
    return the password expected for it ('' = no password). }
  TBinkAuthEvent = function(
    const Remote : TFTNAddress;
    out Password : String) : Boolean of object;

  TBinkTxState = (txGNF, txReadS, txWaitGet, txWLA);
  TBinkRxState = (rxWaitF, rxReceD, rxEOB);

  TBinkSession = class
  private
    FConfig    : TBinkConfig;
    FSock      : TBinkSocket;
    FOwnsSock  : Boolean;
    FInbound   : TBinkInbound;
    FInboundUnsecure : TBinkInbound;
    FReceived  : TStringList;
    FOutbound  : TBinkOutbound;
    FState     : TBinkState;

    FRemote      : array of TFTNAddress;
    FRemoteStr   : String;
    FRemotePwd   : String;
    FGotADR      : Boolean;
    FGotPWD      : Boolean;
    FSecure      : Boolean;
    FChallenge   : String;   { CRAM challenge we offered (answering) }
    FRemoteChallenge : String; { CRAM challenge offered to us (originating) }
    FRemoteHash  : String;     { hash chosen from the remote's list }

    FRemoteNR    : Boolean;    { remote sent OPT NR: send files NR style }
    FRemoteCrypt : Boolean;    { remote sent OPT CRYPT }
    FCryptOffered : Boolean;   { we sent OPT CRYPT before M_PWD }
    FCrypt       : Boolean;    { stream encryption is active }
    FCryptPassword : String;
    FRemotePLZ   : Boolean;    { remote offered PLZ compression }
    FPlz         : Boolean;    { PLZ mode is active (both offered) }
    FPlzOff      : Boolean;    { switched off by NZ: never re-enable }
    FWireSent    : Int64;      { data payload bytes actually sent }

    FLastError   : String;
    FRemoteBusy  : Boolean;
    FCancelled   : Boolean;
    FLastActivity: QWord;

    FOnLog           : TBinkLogEvent;
    FOnAuth          : TBinkAuthEvent;
    FOnAuthenticated : TNotifyEvent;
    FOnProgress      : TBinkProgressEvent;
    FLastPub         : QWord;
    FRemSys, FRemSysop, FRemLoc, FRemVer : String;

    { transmit side }
    FOutItems  : TFPList;           { TBinkOutItem refs, in sending order }
    FNextFile  : Integer;
    FBso       : TBinkSpool;          { BSO spool to take mail from, or nil }
    FBsoOut    : TBinkOutbound;     { what we collected from FBso }
    FLocked    : array of TFTNAddress;   { .bsy flags we hold }
    FOwnsOutbound : Boolean;
    FOriginating  : Boolean;
    FLogPrefix : String;
    FKnown     : TBinkKnownFiles;   { owns every file we are sending }
    FResend    : TFPList;           { known files re-requested by M_GET }
    FCurrent   : TBinkTransfer;     { file whose data is being sent }
    FTxState   : TBinkTxState;
    FQueue     : TBinkCommandQueue; { "TheQueue": M_GET / M_GOT / M_SKIP }
    FBlock     : array of Byte;

    { receive side }
    FRxState   : TBinkRxState;
    FRecv      : TBinkTransfer;

    FFilesSent     : Integer;
    FFilesReceived : Integer;
    FBytesSent     : Int64;
    FBytesReceived : Int64;

    function  GetRemoteCount : Integer;
    function  GetRemoteAddr(Index : Integer) : TFTNAddress;

    procedure Log(const Msg : String);
    procedure Touch;
    procedure Publish(Force : Boolean);
    procedure Fail(const Msg : String);
    procedure FailRemote(const What, Msg : String);
    procedure AbortSession(const Msg : String);

    procedure SendCmd(Cmd : Byte; const Args : String);
    procedure SendBanner;
    procedure SendADR;
    procedure WaitFrame(out F : TBinkFrame);
    procedure RememberADR(const S : String);
    procedure LogNul(const F : TBinkFrame);
    procedure UnexpectedFrame(const F : TBinkFrame);

    { session setup }
    procedure WaitRemoteADR(const Expect : TFTNAddress);
    procedure WaitOK;
    procedure WaitRemoteAuth;
    procedure Authenticate;

    { transfer stage }
    procedure Transfer;
    procedure HandleFrame(const F : TBinkFrame);
    function  TransferComplete : Boolean;
    function  PendingCount : Integer;
    function  TxCanProduce : Boolean;
    procedure Cleanup;

    { receive routine }
    procedure StartReceive(const Args : String);
    procedure ReceiveData(const F : TBinkFrame);
    procedure FinishReceive;
    procedure AbandonReceive;

    { transmit routine }
    procedure TxStep;
    procedure StartNextFile;
    function  BeginSend(T : TBinkTransfer; AllowNR : Boolean) : Boolean;
    procedure ParseOpts(const S : String);
    procedure StartCrypt(const Password : String);
    procedure PrepareBso;
    procedure RejectBusy(const Msg : String);
    procedure DisablePlz;
    procedure SendBlock;
    procedure FinishCurrent;

    { ProcessTheQueue }
    procedure QueuePush(Cmd : TBinkQueueCommand; const Info : TBinkFileInfo);
    procedure ProcessQueue;
    function  FindKnown(const Item : TBinkQueueItem) : TBinkTransfer;
    procedure DoGet(Item : TBinkQueueItem);
    procedure DoGot(Item : TBinkQueueItem);
    procedure DoSkip(Item : TBinkQueueItem);
    procedure DropTransfer(T : TBinkTransfer);
    procedure FinalizeSent(T : TBinkTransfer);

    function  CurInbound : TBinkInbound;
    function  Execute(Originating : Boolean;
                const Node : TBinkNodeInfo) : Boolean;

  public
    constructor Create(const AConfig : TBinkConfig);
    destructor Destroy; override;

    { Calls Node.Host:Node.Port, runs the whole session and returns
      True if it completed successfully. }
    function Originate(const Node : TBinkNodeInfo) : Boolean;

    { Runs the answering side of a session on an accepted socket.  The
      caller still owns (and frees) the socket. }
    function Answer(ASocket : TBinkSocket) : Boolean;

    { Ask a running session to stop as soon as possible. }
    procedure Cancel;

    { Where received files go.  nil = refuse (M_SKIP) everything. }
    property Inbound : TBinkInbound
      read FInbound write FInbound;

    { Where files go when the remote did not authenticate with a password
      (not Secure).  nil = the same directory as Inbound. }
    property InboundUnsecure : TBinkInbound
      read FInboundUnsecure write FInboundUnsecure;

    { Full paths of the files received so far (complete ones only). }
    property Received : TStringList read FReceived;

    { Files to send.  Read when the transfer stage starts. }
    property Outbound : TBinkOutbound
      read FOutbound write FOutbound;

    { When True the session frees Outbound itself. }
    property OwnsOutbound : Boolean
      read FOwnsOutbound write FOwnsOutbound;

    { A BSO spool: everything queued there for the remote's addresses
      is sent, and the addresses' .bsy flags are held for the
      session.  May be combined with Outbound. }
    property Bso : TBinkSpool
      read FBso write FBso;

    { Prepended to every log line, e.g. '[#3] '. }
    property LogPrefix : String
      read FLogPrefix write FLogPrefix;

    property OnLog : TBinkLogEvent
      read FOnLog write FOnLog;

    { Called from the session's thread, now and then, with what it is doing. }
    property OnProgress : TBinkProgressEvent
      read FOnProgress write FOnProgress;

    { Answering side only. Without a handler, every address is
      accepted and Config.Password is the password. }
    property OnAuth : TBinkAuthEvent
      read FOnAuth write FOnAuth;

    { Fired just after authentication succeeded and before the
      outbound list is read: the place to choose Outbound for the
      remote that just called. }
    property OnAuthenticated : TNotifyEvent
      read FOnAuthenticated write FOnAuthenticated;

    property State : TBinkState read FState;
    property RemoteCount : Integer read GetRemoteCount;
    property RemoteAddr[Index : Integer] : TFTNAddress
      read GetRemoteAddr;
    property RemoteAddresses : String read FRemoteStr;
    property Secure : Boolean read FSecure;
    property Originating : Boolean read FOriginating;
    property LastError : String read FLastError;
    property RemoteBusy : Boolean read FRemoteBusy;
    property FilesSent : Integer read FFilesSent;
    property FilesReceived : Integer read FFilesReceived;
    property BytesSent : Int64 read FBytesSent;
    property BytesReceived : Int64 read FBytesReceived;
  end;

implementation

uses
  DateUtils,
  BinkUtil;

const
  BLOCK_SIZE = 16383;     { data frame size; the PLZ limit (FTS-1029) }
  OUT_LIMIT  = 65536;     { queue more data only below this backlog }
  MAX_ADDRS  = 32;

{ ------------------------------------------------------------------ }

function SafeEqual(const A, B : String) : Boolean;
var
  I, D : Integer;
begin
  { compares without leaking where the first difference is }
  D := Length(A) xor Length(B);

  for I := 1 to Length(A) do
    if I <= Length(B) then
      D := D or (Ord(A[I]) xor Ord(B[I]));

  Result := D = 0;
end;

function Rfc822Now : String;
begin
  Result := FormatDateTime(
    'ddd, dd mmm yyyy hh:nn:ss',
    LocalTimeToUniversal(Now)) + ' GMT';
end;

function InfoOf(T : TBinkTransfer) : TBinkFileInfo;
begin
  Result := Default(TBinkFileInfo);
  Result.FileName  := T.FileName;
  Result.Size      := T.FileSize;
  Result.TimeStamp := T.UnixTime;
  Result.Offset    := T.Offset;
end;

{ ------------------------------------------------------------------ }

constructor TBinkSession.Create(const AConfig : TBinkConfig);
begin
  inherited Create;

  FConfig := AConfig;
  FReceived := TStringList.Create;

  if FConfig.Timeout <= 0 then
    FConfig.Timeout := BINK_DEFAULT_TIMEOUT;

  FState    := bsDisconnected;
  FOutItems := TFPList.Create;
  FKnown    := TBinkKnownFiles.Create;
  FResend   := TFPList.Create;
  FQueue    := TBinkCommandQueue.Create;
  SetLength(FBlock, BLOCK_SIZE);
end;

destructor TBinkSession.Destroy;
begin
  Cleanup;
  FReceived.Free;

  if FOwnsSock then
    FSock.Free;

  FQueue.Free;
  FResend.Free;
  FKnown.Free;
  FOutItems.Free;
  FBsoOut.Free;

  if FOwnsOutbound then
    FOutbound.Free;

  inherited Destroy;
end;

function TBinkSession.GetRemoteCount : Integer;
begin
  Result := Length(FRemote);
end;

function TBinkSession.GetRemoteAddr(Index : Integer) : TFTNAddress;
begin
  Result := FRemote[Index];
end;

procedure TBinkSession.Log(const Msg : String);
begin
  if Assigned(FOnLog) then
    FOnLog(FLogPrefix + Msg);
end;

procedure TBinkSession.Touch;
begin
  FLastActivity := GetTickCount64;
end;

procedure TBinkSession.Publish(Force : Boolean);
var
  P : TBinkProgress;
  T : QWord;
begin
  if not Assigned(FOnProgress) then
    Exit;

  T := GetTickCount64;

  if (not Force) and (T - FLastPub < 100) then
    Exit;

  FLastPub := T;
  P := Default(TBinkProgress);
  P.State := FState;
  P.Originating := FOriginating;
  P.Remote := FRemoteStr;
  P.SysName := FRemSys;
  P.Sysop := FRemSysop;
  P.Location := FRemLoc;
  P.Version := FRemVer;
  P.Secure := FSecure;
  P.Plz := FPlz;
  P.Nr := FRemoteNR;
  P.BytesSent := FBytesSent;
  P.BytesReceived := FBytesReceived;
  P.FilesSent := FFilesSent;
  P.FilesReceived := FFilesReceived;

  if FCurrent <> nil then
  begin
    P.TxName := FCurrent.FileName;
    P.TxPos := FCurrent.Position;
    P.TxSize := FCurrent.FileSize;
  end;

  if FRecv <> nil then
  begin
    P.RxName := FRecv.FileName;
    P.RxPos := FRecv.Position;
    P.RxSize := FRecv.FileSize;
  end;

  FOnProgress(Self, P);
end;

procedure TBinkSession.Cancel;
begin
  FCancelled := True;
end;

procedure TBinkSession.Fail(const Msg : String);
begin
  raise EBinkError.Create(Msg);
end;

procedure TBinkSession.FailRemote(const What, Msg : String);
begin
  if What = 'M_BSY' then
    FRemoteBusy := True;

  raise EBinkError.Create('Remote ' + What + ': ' + Msg);
end;

{ Tell the remote why we are leaving (M_ERR), then fail. }
procedure TBinkSession.AbortSession(const Msg : String);
begin
  try
    if (FSock <> nil) and (not FSock.Closed) then
    begin
      SendCmd(M_ERR, Msg);
      FSock.Flush(2000);
    end;
  except
    { already failing }
  end;

  raise EBinkError.Create(Msg);
end;

procedure TBinkSession.SendCmd(Cmd : Byte; const Args : String);
begin
  SendCommand(FSock, Cmd, Args);
end;

{ ------------------------------------------------------------------ }
{ Session setup                                                       }
{ ------------------------------------------------------------------ }

procedure TBinkSession.SendBanner;
var
  Opts : String;
begin
  Opts := '';

  if FConfig.NonReliable then
    Opts := Opts + ' NR';

  if FConfig.Compress then
    Opts := Opts + ' PLZ';

  if Opts <> '' then
    SendCmd(M_NUL, 'OPT' + Opts);

  if FConfig.SysName <> '' then
    SendCmd(M_NUL, 'SYS ' + FConfig.SysName);

  if FConfig.Sysop <> '' then
    SendCmd(M_NUL, 'ZYZ ' + FConfig.Sysop);

  if FConfig.Location <> '' then
    SendCmd(M_NUL, 'LOC ' + FConfig.Location);

  SendCmd(M_NUL,
    'VER ' + BINK_VERSION_STRING + ' ' + BINK_PROTOCOL_STRING);

  SendCmd(M_NUL, 'TIME ' + Rfc822Now);
end;

procedure TBinkSession.SendADR;
var
  S : String;
  I : Integer;
begin
  S := AddressToString5D(FConfig.Address, FConfig.Domain);

  for I := 0 to High(FConfig.Akas) do
    S := S + ' ' + AddressToString5D(FConfig.Akas[I], FConfig.Domain);

  SendCmd(M_ADR, S);
end;

{ Waits for the next complete frame; raises on timeout, cancel or
  loss of connection.  Frames already buffered are always delivered
  first, even if the peer has closed the connection since. }
procedure TBinkSession.WaitFrame(out F : TBinkFrame);
var
  Deadline : QWord;
begin
  Deadline := GetTickCount64 + QWord(FConfig.Timeout) * 1000;

  while not ReceiveFrame(FSock, F, FPlz) do
  begin
    if FCancelled then
      Fail('Session cancelled');

    if FSock.Closed then
      Fail('Connection lost: ' + FSock.LastError);

    if GetTickCount64 > Deadline then
      Fail('Timeout waiting for remote');

    FSock.Pump(200);
  end;

  Touch;
end;

procedure TBinkSession.RememberADR(const S : String);
var
  Tmp : array[0..MAX_ADDRS - 1] of TFTNAddress;
  N, I : Integer;
begin
  N := ParseAddressList(S, Tmp);

  FRemoteStr := Trim(S);
  SetLength(FRemote, N);

  for I := 0 to N - 1 do
    FRemote[I] := Tmp[I];

  FGotADR := True;
end;

procedure TBinkSession.LogNul(const F : TBinkFrame);
var
  S, H, C : String;
begin
  S := FrameDataAsString(F);
  Log('Remote: ' + S);

  if Copy(S, 1, 4) = 'SYS ' then
    FRemSys := Copy(S, 5, MaxInt)
  else if Copy(S, 1, 4) = 'ZYZ ' then
    FRemSysop := Copy(S, 5, MaxInt)
  else if Copy(S, 1, 4) = 'LOC ' then
    FRemLoc := Copy(S, 5, MaxInt)
  else if Copy(S, 1, 4) = 'VER ' then
    FRemVer := Copy(S, 5, MaxInt);

  if Copy(S, 1, 4) = 'OPT ' then
  begin
    if (FRemoteChallenge = '') and
       FindChallenge(Copy(S, 5, MaxInt), H, C) then
    begin
      FRemoteHash := H;
      FRemoteChallenge := C;
    end;

    ParseOpts(Copy(S, 5, MaxInt));
  end;
end;

{ Protocol options other than CRAM: NR (FTS-1028) and PLZ (FTS-1029).
  They may arrive at any time during the session. }
procedure TBinkSession.ParseOpts(const S : String);
var
  I : Integer;
  W : String;

  procedure Check;
  begin
    if UpperCase(W) = 'NR' then
    begin
      if not FRemoteNR then
        Log('Remote requested non-reliable (NR) mode');

      FRemoteNR := True;
    end
    else if UpperCase(W) = 'CRYPT' then
      FRemoteCrypt := True
    else if UpperCase(W) = 'PLZ' then
    begin
      FRemotePLZ := True;

      if FConfig.Compress and (not FPlzOff) and (not FPlz) then
      begin
        FPlz := True;
        Log('PLZ compression active');
      end;
    end;

    W := '';
  end;

begin
  W := '';

  for I := 1 to Length(S) do
  begin
    if S[I] in [' ', #9, #0] then
      Check
    else
      W := W + S[I];
  end;

  Check;
end;

{ Switch the connection to CRYPT.  Called right after the M_OK has
  been sent (answering) or received (originating); both are the last
  plaintext frames.  The originator's outgoing stream is keyed with
  the password, the answerer's with "-" then the password. }
procedure TBinkSession.StartCrypt(const Password : String);
var
  A, B : TBinkCipher;
begin
  CipherInit(A, Password);
  CipherInitDash(B, Password);

  if FOriginating then
    FSock.StartCrypt(A, B)
  else
    FSock.StartCrypt(B, A);

  FCrypt := True;
  Log('CRYPT encryption active');
end;

{ NZ (FTS-1029): drop out of PLZ mode for the rest of the session. }
procedure TBinkSession.DisablePlz;
begin
  if FPlz then
    Log('Remote switched PLZ compression off (NZ)');

  FPlz := False;
  FPlzOff := True;
end;

procedure TBinkSession.UnexpectedFrame(const F : TBinkFrame);
begin
  if F.FrameType = ftData then
    AbortSession('Unexpected data frame')
  else
    AbortSession('Unexpected ' +
      CommandName(IDToCommand(F.CommandID)));
end;

{ Originating side, Table 1 states S3 / S4: wait for the answering
  side's M_ADR and check it presented the address we called. }
procedure TBinkSession.WaitRemoteADR(const Expect : TFTNAddress);
var
  F : TBinkFrame;
  I : Integer;
  Found : Boolean;
begin
  FGotADR := False;

  while not FGotADR do
  begin
    WaitFrame(F);

    if F.FrameType <> ftCommand then
      Continue;   { data before auth: ignore }

    case F.CommandID of
      M_NUL : LogNul(F);
      M_ADR : RememberADR(FrameDataAsString(F));
      M_ERR : FailRemote('M_ERR', FrameDataAsString(F));
      M_BSY : FailRemote('M_BSY', FrameDataAsString(F));
      M_PWD, M_OK, M_FILE, M_EOB, M_GOT, M_GET, M_SKIP :
        UnexpectedFrame(F);
    else
      { unknown command: ignore }
    end;
  end;

  if Expect.Zone <> 0 then
  begin
    Found := False;

    for I := 0 to High(FRemote) do
      if SameAddress(FRemote[I], Expect) then
        Found := True;

    if not Found then
      AbortSession('Bad address: expected ' +
        AddressToString(Expect) + ', remote presented "' +
        FRemoteStr + '"');
  end;
end;

{ Originating side, Table 1 state S6. }
procedure TBinkSession.WaitOK;
var
  F : TBinkFrame;
begin
  while True do
  begin
    WaitFrame(F);

    if F.FrameType <> ftCommand then
      Continue;

    case F.CommandID of
      M_NUL : LogNul(F);
      M_ADR : ;   { repeated address list: ignore }
      M_OK  :
      begin
        FSecure := FRemotePwd <> '-';
        Log('Password accepted (' + FrameDataAsString(F) + ')');

        { a "non-secure" M_OK means the remote did not accept the
          password, so it will not encrypt either }
        if FCryptOffered and FRemoteCrypt and FSecure and
           (LowerCase(Trim(FrameDataAsString(F))) = 'secure') then
          StartCrypt(FCryptPassword);

        Exit;
      end;
      M_ERR : FailRemote('M_ERR', FrameDataAsString(F));
      M_BSY : FailRemote('M_BSY', FrameDataAsString(F));
      M_PWD, M_FILE, M_EOB, M_GOT, M_GET, M_SKIP :
        UnexpectedFrame(F);
    else
    end;
  end;
end;

{ Answering side, Table 2 states R1 / R3: collect M_ADR and M_PWD
  (in whatever order they arrive). }
procedure TBinkSession.WaitRemoteAuth;
var
  F : TBinkFrame;
begin
  FGotADR := False;
  FGotPWD := False;

  while not (FGotADR and FGotPWD) do
  begin
    WaitFrame(F);

    if F.FrameType <> ftCommand then
      Continue;

    case F.CommandID of
      M_NUL : LogNul(F);
      M_ADR : RememberADR(FrameDataAsString(F));
      M_PWD :
      begin
        FRemotePwd := FrameDataAsString(F);
        FGotPWD := True;
      end;
      M_ERR : FailRemote('M_ERR', FrameDataAsString(F));
      M_BSY : FailRemote('M_BSY', FrameDataAsString(F));
      M_OK, M_FILE, M_EOB, M_GOT, M_GET, M_SKIP :
        UnexpectedFrame(F);
    else
    end;
  end;
end;

{ Answering side, Table 2 states R2 / R4. }
procedure TBinkSession.Authenticate;
var
  I : Integer;
  Pwd, Expected : String;
  Known : Boolean;
  KnownCount : Integer;
  UseCrypt : Boolean;
begin
  UseCrypt := False;

  if Length(FRemote) = 0 then
    AbortSession('Bad address: no valid address in M_ADR');

  Expected := '';
  KnownCount := 0;

  { An address we do not know is only left out (a system presents all its
    AKAs); the session is refused when none of them is known. }
  for I := 0 to High(FRemote) do
  begin
    Pwd := FConfig.Password;
    Known := True;

    if Assigned(FOnAuth) then
      Known := FOnAuth(FRemote[I], Pwd);

    if not Known then
    begin
      Log('Ignoring unknown address ' + AddressToString(FRemote[I]));
      Continue;
    end;

    if KnownCount = 0 then
      Expected := Pwd
    else if Pwd <> Expected then
      AbortSession('Inconsistent password settings');

    FRemote[KnownCount] := FRemote[I];
    Inc(KnownCount);
  end;

  if KnownCount = 0 then
  begin
    Log('Rejected unknown address ' + AddressToString(FRemote[0]));
    AbortSession('Bad address');
  end;

  SetLength(FRemote, KnownCount);

  if Expected <> '' then
  begin
    if (FChallenge <> '') and
       (CompareText(Copy(FRemotePwd, 1, Length(CRAM_PREFIX)),
                    CRAM_PREFIX) = 0) then
    begin
      if not CramVerify(Expected, FChallenge, FRemotePwd) then
      begin
        Log('CRAM-MD5 mismatch from ' + FRemoteStr);
        AbortSession('Incorrect password');
      end;

      Log('CRAM-MD5 authentication');
      UseCrypt := (not FConfig.NoCrypt) and FRemoteCrypt;
    end
    else
    begin
      if FConfig.RequireCram then
      begin
        Log('Cleartext password refused from ' + FRemoteStr);
        AbortSession('CRAM-MD5 authentication required');
      end;

      if not SafeEqual(Expected, FRemotePwd) then
      begin
        Log('Password mismatch from ' + FRemoteStr);
        AbortSession('Incorrect password');
      end;
    end;

    FSecure := True;

    if UseCrypt then
      SendCmd(M_NUL, 'OPT CRYPT');

    SendCmd(M_OK, 'secure');

    if UseCrypt then
      StartCrypt(Expected);
  end
  else
  begin
    FSecure := False;
    SendCmd(M_OK, 'non-secure');
  end;

  Log('Remote ' + FRemoteStr + ' authenticated (' +
    BoolToStr(FSecure, 'secure', 'non-secure') + ')');
end;

{ ------------------------------------------------------------------ }
{ Entry points                                                        }
{ ------------------------------------------------------------------ }

function TBinkSession.Originate(const Node : TBinkNodeInfo) : Boolean;
begin
  Result := Execute(True, Node);
end;

function TBinkSession.Answer(ASocket : TBinkSocket) : Boolean;
var
  Dummy : TBinkNodeInfo;
begin
  if FOwnsSock then
    FSock.Free;

  FSock := ASocket;
  FOwnsSock := False;

  Dummy := Default(TBinkNodeInfo);
  Result := Execute(False, Dummy);
end;

function TBinkSession.Execute(
  Originating : Boolean;
  const Node : TBinkNodeInfo) : Boolean;
var
  Port : Word;
begin
  Result := False;

  FLastError  := '';
  FRemoteBusy := False;
  FCancelled  := False;
  FOriginating := Originating;
  FSecure     := False;
  FChallenge  := '';
  FRemoteChallenge := '';
  FRemoteHash := '';
  FRemoteNR := False;
  FRemoteCrypt := False;
  FCryptOffered := False;
  FCrypt := False;
  FCryptPassword := '';
  FRemotePLZ := False;
  FPlz := False;
  FPlzOff := False;
  FWireSent := 0;
  FFilesSent := 0;     FFilesReceived := 0;
  FReceived.Clear;
  FBytesSent := 0;     FBytesReceived := 0;
  SetLength(FRemote, 0);
  FRemSys := ''; FRemSysop := ''; FRemLoc := ''; FRemVer := '';
  Touch;
  Publish(True);

  try
    try
      if Originating then
      begin
        Port := Node.Port;

        if Port = 0 then
          Port := BINK_DEFAULT_PORT;

        FSock := TBinkSocket.Create;
        FOwnsSock := True;

        Log(Format('Connecting to %s:%d', [Node.Host, Port]));
        FSock.Connect(Node.Host, Port);
        FState := bsConnected;
        Log('Connected');

        { Table 1: S1 - banner and our address immediately, M_PWD only
          once the answering side's M_ADR has been seen }
        SendBanner;
        SendADR;

        FState := bsAuth;
        WaitRemoteADR(Node.Address);

        if Node.Password = '' then
          FRemotePwd := '-'
        else if FRemoteChallenge <> '' then
        begin
          FRemotePwd := CramPassword(
            Node.Password, FRemoteHash, FRemoteChallenge);
          Log('Using CRAM-' + FRemoteHash + ' authentication');
        end
        else
        begin
          FRemotePwd := Node.Password;
          Log('Remote offers no CRAM-MD5: sending password in cleartext');
        end;

        { CRYPT needs a real password and CRAM (so the password never
          travels in clear); the answering side confirms before M_OK }
        if (not FConfig.NoCrypt) and (Node.Password <> '') and
           (FRemoteChallenge <> '') then
        begin
          FCryptOffered := True;
          FCryptPassword := Node.Password;
          SendCmd(M_NUL, 'OPT CRYPT');
        end;

        SendCmd(M_PWD, FRemotePwd);
        WaitOK;
      end
      else
      begin
        FState := bsConnected;
        Log('Incoming call from ' + FSock.RemoteAddress);

        { Table 2: R0 -- the CRAM-MD5 challenge goes out first }
        FChallenge := NewChallenge;
        SendCmd(M_NUL, 'OPT ' + CRAM_PREFIX + 'MD5-' + FChallenge);
        SendBanner;
        SendADR;

        FState := bsAuth;
        WaitRemoteAuth;
        Authenticate;
      end;

      Transfer;

      FState := bsDone;
      Log(Format(
        'Session complete: sent %d file(s) / %d bytes, ' +
        'received %d file(s) / %d bytes',
        [FFilesSent, FBytesSent, FFilesReceived, FBytesReceived]));

      if FWireSent <> FBytesSent then
        Log(Format('PLZ compression: %d data bytes sent as %d (%d%%)',
          [FBytesSent, FWireSent,
           (FWireSent * 100) div FBytesSent]));

      Result := True;
    except
      on E : Exception do
      begin
        FLastError := E.Message;
        Log('Session failed: ' + E.Message);
      end;
    end;
  finally
    Cleanup;

    if FSock <> nil then
    begin
      FSock.Flush(3000);
      FSock.Disconnect;
    end;

    if FState <> bsDone then
      FState := bsDisconnected;
  end;
end;

{ Closes open files (partial inbound files stay on disk for a later
  M_GET resume). }
procedure TBinkSession.Cleanup;
var
  I : Integer;
begin
  if FRecv <> nil then
  begin
    FRecv.Free;
    FRecv := nil;
  end;

  FCurrent := nil;
  FResend.Clear;

  for I := 0 to FKnown.Files.Count - 1 do
    FKnown.Files.Items[I].Close;

  FKnown.Clear;
  FQueue.Clear;

  { release the BSO .bsy flags last, after files were finalized }
  for I := 0 to High(FLocked) do
    FBso.Unlock(FLocked[I]);

  SetLength(FLocked, 0);
end;

{ Tell the remote we cannot serve it right now (M_BSY), then fail. }
procedure TBinkSession.RejectBusy(const Msg : String);
begin
  FRemoteBusy := True;

  try
    if (FSock <> nil) and (not FSock.Closed) then
    begin
      SendCmd(M_BSY, Msg);
      FSock.Flush(2000);
    end;
  except
    { already failing }
  end;

  raise EBinkError.Create(Msg);
end;

{ Lock the BSO flag of every address the remote presented and collect
  what is queued for them.  Hold flavour goes out only when the remote
  called us. }
procedure TBinkSession.PrepareBso;
var
  I, N, Total : Integer;
  Locked : Boolean;
begin
  if FBsoOut = nil then
    FBsoOut := TBinkOutbound.Create
  else
    FBsoOut.Clear;

  Total := 0;

  for I := 0 to High(FRemote) do
  begin
    try
      Locked := FBso.TryLock(FRemote[I]);
    except
      on E : EBinkError do
      begin
        { a local configuration problem, not a busy link }
        Log('BSO outbound error: ' + E.Message);
        AbortSession('Cannot access outbound for ' +
          AddressToString(FRemote[I]));
      end;
    end;

    if not Locked then
    begin
      Log('Link ' + AddressToString(FRemote[I]) +
        ' is busy (its .bsy flag is held by another session)');
      RejectBusy('Link busy');
    end;

    SetLength(FLocked, Length(FLocked) + 1);
    FLocked[High(FLocked)] := FRemote[I];

    N := FBso.Collect(FRemote[I], not FOriginating, FBsoOut);
    Inc(Total, N);
  end;

  Log(Format('%d file(s) found in the BSO outbound', [Total]));
end;

{ ------------------------------------------------------------------ }
{ File transfer stage (Table 3)                                       }
{ ------------------------------------------------------------------ }

function TBinkSession.PendingCount : Integer;
var
  I : Integer;
begin
  Result := 0;

  for I := 0 to FKnown.Files.Count - 1 do
    if FKnown.Files.Items[I].Pending then
      Inc(Result);
end;

function TBinkSession.TxCanProduce : Boolean;
begin
  Result := FTxState in [txGNF, txReadS];
end;

{ Section 6.3, condition 3. }
function TBinkSession.TransferComplete : Boolean;
begin
  Result :=
    (FRxState = rxEOB) and
    (FTxState = txWLA) and
    (FCurrent = nil) and
    (FResend.Count = 0) and
    (FQueue.Count = 0) and
    (PendingCount = 0);
end;

procedure TBinkSession.Transfer;
var
  F        : TBinkFrame;
  Wait, N, I : Integer;
  PrevOut, OutNow : Integer;
begin
  FState   := bsTransfer;
  FRxState := rxWaitF;
  FTxState := txGNF;
  FNextFile := 0;

  if Assigned(FOnAuthenticated) then
    FOnAuthenticated(Self);

  FOutItems.Clear;

  if FBso <> nil then
    PrepareBso;

  if FOutbound <> nil then
    for I := 0 to FOutbound.Count - 1 do
      FOutItems.Add(FOutbound.Items[I]);

  if FBsoOut <> nil then
    for I := 0 to FBsoOut.Count - 1 do
      FOutItems.Add(FBsoOut.Items[I]);

  Log(Format('%d file(s) queued for the remote', [FOutItems.Count]));

  Touch;
  PrevOut := 0;
  Publish(True);

  while True do
  begin
    if FCancelled then
      AbortSession('Session cancelled');

    { T1: wait for input -- but do not wait at all if we still have
      something to put on the wire }
    if TxCanProduce and (FSock.OutPending < OUT_LIMIT) then
      Wait := 0
    else
      Wait := 250;

    FSock.Pump(Wait);

    { T2: Receive routine }
    while ReceiveFrame(FSock, F, FPlz) do
    begin
      Touch;
      HandleFrame(F);
    end;

    ProcessQueue;

    { T3: Transmit routine }
    N := 0;

    while TxCanProduce and (FSock.OutPending < OUT_LIMIT) and
          (N < 8) do
    begin
      TxStep;
      ProcessQueue;
      Inc(N);
    end;

    Publish(False);

    if TransferComplete then
    begin
      Log('Both sides finished, session complete');
      Break;
    end;

    { output made progress counts as activity }
    OutNow := FSock.OutPending;

    if OutNow < PrevOut then
      Touch;

    PrevOut := OutNow;

    if FSock.Closed and (FSock.Available = 0) then
      Fail('Connection lost: ' + FSock.LastError);

    if GetTickCount64 - FLastActivity >
       QWord(FConfig.Timeout) * 1000 then
      Fail('Timeout: no activity for ' +
           IntToStr(FConfig.Timeout) + ' seconds');
  end;
end;

{ Table 4: the Receive routine, driven by one frame at a time. }
procedure TBinkSession.HandleFrame(const F : TBinkFrame);
var
  S    : String;
  Info : TBinkFileInfo;
begin
  if F.FrameType = ftData then
  begin
    if FRxState = rxReceD then
      ReceiveData(F);
    { otherwise: data we did not ask for (e.g. in flight after our
      M_GET or M_SKIP) -- ignore }

    Exit;
  end;

  S := FrameDataAsString(F);

  case F.CommandID of

    M_NUL :
      LogNul(F);

    M_ERR :
      FailRemote('M_ERR', S);

    M_BSY :
      FailRemote('M_BSY', S);

    M_GET :
      if ParseGET(S, Info) then
      begin
        if Info.NZ then
          DisablePlz;

        QueuePush(bqcGET, Info)
      end
      else
        Log('Ignoring unparsable M_GET: ' + S);

    M_GOT :
      if ParseGOT(S, Info) then
        QueuePush(bqcGOT, Info)
      else
        Log('Ignoring unparsable M_GOT: ' + S);

    M_SKIP :
      if ParseSKIP(S, Info) then
        QueuePush(bqcSKIP, Info)
      else
        Log('Ignoring unparsable M_SKIP: ' + S);

    M_EOB :
    begin
      if FRxState = rxReceD then
        AbandonReceive;

      FRxState := rxEOB;
      Log('Remote end of batch');
    end;

    M_FILE :
      StartReceive(S);

    M_ADR, M_PWD, M_OK :
      UnexpectedFrame(F);

  else
    { unknown command: ignore }
  end;
end;

{ ------------------------------------------------------------------ }
{ Receive routine                                                     }
{ ------------------------------------------------------------------ }

procedure TBinkSession.AbandonReceive;
begin
  if FRecv <> nil then
  begin
    Log(Format('Receive of %s interrupted at %d of %d bytes ' +
      '(partial file kept)',
      [FRecv.FileName, FRecv.Position, FRecv.FileSize]));

    FRecv.Free;   { closes the stream; the .part file stays }
    FRecv := nil;
  end;

  FRxState := rxWaitF;
end;

{ RxWaitF on M_FILE + RxAccF }
procedure TBinkSession.StartReceive(const Args : String);
var
  Info : TBinkFileInfo;
  Have : Int64;
  T    : TBinkTransfer;
  Part : String;
  EmptyPath : String;
begin
  if FRxState = rxReceD then
    AbandonReceive;

  FRxState := rxWaitF;

  if not ParseFILE(Args, Info) then
    AbortSession('M_FILE: cannot parse args');

  { Refuse (non destructively) anything we cannot or will not take }
  if (CurInbound = nil) or
     (not TBinkInbound.IsSafeName(Info.FileName)) then
  begin
    Log('Refusing ' + Info.FileName);
    SendCmd(M_SKIP, BuildSKIP(Info));
    Exit;
  end;

  { Already have this exact file: acknowledge so remote can drop it }
  if CurInbound.HasComplete(Info.FileName, Info.Size, Info.TimeStamp) then
  begin
    Log('Already have ' + Info.FileName + ', acknowledging');
    SendCmd(M_GOT, BuildGOT(Info));
    Exit;
  end;

  if Info.Size = 0 then
  begin
    try
      EmptyPath := CurInbound.StoreEmpty(Info.FileName, Info.TimeStamp);
    except
      on E : Exception do
      begin
        Log('Cannot create ' + Info.FileName + ': ' + E.Message);
        SendCmd(M_SKIP, BuildSKIP(Info));
        Exit;
      end;
    end;

    Inc(FFilesReceived);
    FReceived.Add(EmptyPath);
    Log('Received ' + Info.FileName + ' (empty)');
    SendCmd(M_GOT, BuildGOT(Info));
    Exit;
  end;

  Have := CurInbound.PartialSize(
    Info.FileName, Info.Size, Info.TimeStamp);

  if Have >= Info.Size then
  begin
    { stale / oversized partial: start again }
    CurInbound.DiscardPartial(
      Info.FileName, Info.Size, Info.TimeStamp);
    Have := 0;
  end;

  if Info.NR or (Info.Offset <> Have) then
  begin
    { Remote is sending from a different place than we want to
      continue from: ask for the right offset and wait for the new
      M_FILE.  Data frames for this announcement are ignored. }
    Info.Offset := Have;

    if Have > 0 then
      Log(Format('Resuming %s at offset %d', [Info.FileName, Have]))
    else
      Log('Requesting ' + Info.FileName + ' from the start');

    SendCmd(M_GET, BuildGET(Info));
    Exit;
  end;

  Part := CurInbound.PartialPath(
    Info.FileName, Info.Size, Info.TimeStamp);

  T := TBinkTransfer.Create;
  T.Direction := btdReceive;
  T.FileName  := Info.FileName;
  T.LocalPath := Part;
  T.FileSize  := Info.Size;
  T.UnixTime  := Info.TimeStamp;
  T.Offset    := Have;

  try
    T.OpenForReceive;
  except
    on E : Exception do
    begin
      Log('Cannot create ' + Part + ': ' + E.Message);
      T.Free;
      SendCmd(M_SKIP, BuildSKIP(Info));
      Exit;
    end;
  end;

  FRecv := T;
  FRxState := rxReceD;

  Log(Format('Receiving %s (%d bytes) from offset %d',
    [T.FileName, T.FileSize, T.Offset]));
end;

{ RxReceD + RxWriteD }
procedure TBinkSession.ReceiveData(const F : TBinkFrame);
var
  N : Integer;
begin
  N := Length(F.Data);

  if FRecv.Position + N > FRecv.FileSize then
    AbortSession('More data received than announced for ' +
      FRecv.FileName);

  try
    FRecv.Stream.WriteBuffer(F.Data[0], N);
  except
    on E : Exception do
      AbortSession('Write error on ' + FRecv.LocalPath + ': ' +
        E.Message);
  end;

  FRecv.Position := FRecv.Position + N;
  Inc(FBytesReceived, N);

  if FRecv.Complete then
    FinishReceive;
end;

function TBinkSession.CurInbound : TBinkInbound;
begin
  if (not FSecure) and (FInboundUnsecure <> nil) then
    Result := FInboundUnsecure
  else
    Result := FInbound;
end;

procedure TBinkSession.FinishReceive;
var
  T     : TBinkTransfer;
  Final : String;
begin
  T := FRecv;
  FRecv := nil;

  T.Close;

  try
    Final := CurInbound.Finalize(T.LocalPath, T.FileName, T.UnixTime);
  except
    on E : Exception do
    begin
      Final := 'Cannot store ' + T.FileName + ': ' + E.Message;
      T.Free;
      AbortSession(Final);
    end;
  end;

  Inc(FFilesReceived);
  FReceived.Add(Final);
  Log(Format('Received %s (%d bytes) -> %s',
    [T.FileName, T.FileSize, Final]));

  SendCmd(M_GOT, BuildGOT(InfoOf(T)));

  T.Free;
  FRxState := rxWaitF;
end;

{ ------------------------------------------------------------------ }
{ Transmit routine (Table 5)                                          }
{ ------------------------------------------------------------------ }

procedure TBinkSession.TxStep;
begin
  case FTxState of
    txGNF   : StartNextFile;
    txReadS : SendBlock;
    txWaitGet : ;   { NR mode: nothing to send until the M_GET arrives }
    txWLA   : ;
  end;
end;

{ TxGNF }
procedure TBinkSession.StartNextFile;
var
  T    : TBinkTransfer;
  Item : TBinkOutItem;
begin
  { files the remote re-requested come first }
  while FResend.Count > 0 do
  begin
    T := TBinkTransfer(FResend[0]);
    FResend.Delete(0);

    if BeginSend(T, False) then
      Exit;
  end;

  while FNextFile < FOutItems.Count do
  begin
    Item := TBinkOutItem(FOutItems[FNextFile]);
    Inc(FNextFile);

    if not FileExists(Item.LocalPath) then
    begin
      Log('Skipping missing file ' + Item.LocalPath);
      Continue;
    end;

    if FKnown.Files.FindByName(Item.WireName) <> nil then
    begin
      Log('Skipping ' + Item.LocalPath +
        ': a file named ' + Item.WireName + ' is already being sent');
      Continue;
    end;

    T := FKnown.AddTransfer;
    T.Direction := btdSend;
    T.FileName  := Item.WireName;
    T.LocalPath := Item.LocalPath;
    T.OutItem   := Item;
    T.Offset    := 0;

    if BeginSend(T, True) then
      Exit;
  end;

  { no more files }
  SendCmd(M_EOB, '');
  FTxState := txWLA;
  Log('Sent end of batch');
end;

{ Opens T, announces it with M_FILE and makes it the current file. }
function TBinkSession.BeginSend(
  T : TBinkTransfer;
  AllowNR : Boolean) : Boolean;
var
  Mt : Int64;
  Info : TBinkFileInfo;
  UseNR : Boolean;
begin
  Result := False;

  try
    T.OpenForSend;
  except
    on E : Exception do
    begin
      Log('Cannot open ' + T.LocalPath + ': ' + E.Message);
      DropTransfer(T);
      Exit;
    end;
  end;

  Mt := GetFileUnixTime(T.LocalPath);

  if Mt < 0 then
    Mt := 0;

  T.UnixTime := Mt;
  T.Pending  := False;
  T.State    := btsTransferring;

  { NR mode (FTS-1028): announce the file with offset -1 and hold the
    data back until the receiver tells us where to start with M_GET.
    Not for re-sends (they answer an M_GET already) or empty files. }
  UseNR := AllowNR and FRemoteNR and (T.Offset = 0) and
           (T.Remaining > 0);

  Info := InfoOf(T);
  Info.NR := UseNR;

  SendCmd(M_FILE, BuildFILE(Info));

  if UseNR then
    Log(Format('Offering %s (%d bytes), waiting for M_GET (NR mode)',
      [T.FileName, T.FileSize]))
  else
    Log(Format('Sending %s (%d bytes) from offset %d',
      [T.FileName, T.FileSize, T.Offset]));

  FCurrent := T;

  if T.Remaining <= 0 then
    FinishCurrent
  else if UseNR then
    FTxState := txWaitGet
  else
    FTxState := txReadS;

  Result := True;
end;

{ TxReadS }
procedure TBinkSession.SendBlock;
var
  T : TBinkTransfer;
  N : Int64;
  Wire : Integer;
begin
  T := FCurrent;

  if T = nil then
  begin
    FTxState := txGNF;
    Exit;
  end;

  N := T.Remaining;

  if N <= 0 then
  begin
    FinishCurrent;
    Exit;
  end;

  if N > BLOCK_SIZE then
    N := BLOCK_SIZE;

  N := T.Stream.Read(FBlock[0], N);

  if N <= 0 then
    AbortSession('Read error (file changed while sending?): ' +
      T.LocalPath);

  SendDataFrame(FSock, FBlock[0], N, FPlz, Wire);
  Inc(FWireSent, Wire);

  T.Position := T.Position + N;
  Inc(FBytesSent, N);

  if T.Remaining <= 0 then
    FinishCurrent;
end;

{ Last byte queued: the file now waits in PendingFiles for the
  remote's M_GOT / M_GET / M_SKIP. }
procedure TBinkSession.FinishCurrent;
begin
  if FCurrent <> nil then
  begin
    FCurrent.Close;
    FCurrent.Pending := True;
    FCurrent.State := btsPendingAck;
    FCurrent := nil;
  end;

  FTxState := txGNF;
end;

{ ------------------------------------------------------------------ }
{ ProcessTheQueue (Table 6)                                           }
{ ------------------------------------------------------------------ }

procedure TBinkSession.QueuePush(
  Cmd : TBinkQueueCommand;
  const Info : TBinkFileInfo);
var
  Item : TBinkQueueItem;
begin
  Item := TBinkQueueItem.Create;
  Item.Command  := Cmd;
  Item.FileName := Info.FileName;
  Item.FileSize := Info.Size;
  Item.UnixTime := Info.TimeStamp;
  Item.Offset   := Info.Offset;

  FQueue.Push(Item);
end;

function TBinkSession.FindKnown(
  const Item : TBinkQueueItem) : TBinkTransfer;
begin
  if (Item.FileSize >= 0) and (Item.UnixTime >= 0) then
    Result := FKnown.Find(Item.FileName, Item.FileSize, Item.UnixTime)
  else
    Result := FKnown.Files.FindByName(Item.FileName);
end;

{ Forget a file: no longer current, resend candidate or known. }
procedure TBinkSession.DropTransfer(T : TBinkTransfer);
begin
  if T = FCurrent then
  begin
    FCurrent := nil;
    FTxState := txGNF;
  end;

  FResend.Remove(T);
  FKnown.Remove(T);   { frees T, closing its stream }
end;

{ "finalize file": mark as sent in the outbound queue. }
procedure TBinkSession.FinalizeSent(T : TBinkTransfer);
begin
  if T.OutItem <> nil then
    TBinkOutItem(T.OutItem).Owner.MarkSent(TBinkOutItem(T.OutItem));

  Inc(FFilesSent);
  DropTransfer(T);
end;

procedure TBinkSession.ProcessQueue;
var
  Item : TBinkQueueItem;
begin
  while FQueue.Count > 0 do
  begin
    Item := FQueue.Pop;

    try
      case Item.Command of
        bqcGET  : DoGet(Item);
        bqcGOT  : DoGot(Item);
        bqcSKIP : DoSkip(Item);
      else
      end;
    finally
      Item.Free;
    end;
  end;
end;

procedure TBinkSession.DoGet(Item : TBinkQueueItem);
var
  T : TBinkTransfer;
begin
  T := FindKnown(Item);

  if T = nil then
  begin
    Log('Remote requested unknown file ' + Item.FileName);
    Exit;
  end;

  if Item.Offset > T.FileSize then
  begin
    Log('Ignoring M_GET beyond end of ' + T.FileName);
    Exit;
  end;

  if Item.Offset = T.FileSize then
  begin
    { remote already has all of it }
    Log('Remote already has ' + T.FileName);
    FinalizeSent(T);
    Exit;
  end;

  Log(Format('Remote requested %s from offset %d',
    [T.FileName, Item.Offset]));

  T.Offset := Item.Offset;

  if T = FCurrent then
  begin
    { discard what is in progress and restart at the offset }
    T.Stream.Position := Item.Offset;
    T.Position := Item.Offset;
    SendCmd(M_FILE, BuildFILE(InfoOf(T)));
    FTxState := txReadS;
  end
  else
  begin
    { already sent (waiting in PendingFiles): send it again }
    T.Pending := False;
    T.Close;

    if FResend.IndexOf(T) < 0 then
      FResend.Add(T);

    if FTxState = txWLA then
      FTxState := txGNF;
  end;
end;

procedure TBinkSession.DoGot(Item : TBinkQueueItem);
var
  T : TBinkTransfer;
begin
  T := FindKnown(Item);

  if T = nil then
    Exit;   { not a file we know: ignore }

  if T = FCurrent then
    Log('Remote refused (M_GOT) ' + T.FileName + ' mid transfer')
  else
    Log('Remote acknowledged ' + T.FileName);

  FinalizeSent(T);
end;

procedure TBinkSession.DoSkip(Item : TBinkQueueItem);
var
  T : TBinkTransfer;
begin
  T := FindKnown(Item);

  if T = nil then
    Exit;

  { not finalized: the file stays in the outbound for next time }
  Log('Remote will accept ' + T.FileName + ' later (M_SKIP)');
  DropTransfer(T);
end;

end.
