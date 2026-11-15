unit BinkTypes;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

const
  BINK_DEFAULT_PORT    = 24554;

  { Seconds of inactivity (no frame received and no output progress)
    before a session is aborted. }
  BINK_DEFAULT_TIMEOUT = 120;

  BINK_VERSION_STRING  = 'MkBink/0.2';
  BINK_PROTOCOL_STRING = 'binkp/1.0';

type
  EBinkError = class(Exception);

  TBinkState =
  (
    bsDisconnected,
    bsConnected,
    bsAuth,
    bsTransfer,
    bsWaitEOB,
    bsDone
  );

  TFTNAddress = record
    Zone : Word;
    Net  : Word;
    Node : Word;
    Point: Word;
  end;

  { The remote system, as seen by the originating side. }
  TBinkNodeInfo = record
    Address  : TFTNAddress;
    Host     : String;
    Port     : Word;
    Password : String;
  end;

  { Local system identity and session settings (both sides). }
  TBinkConfig = record
    Address  : TFTNAddress;
    Akas     : array of TFTNAddress; { more addresses, presented after Address }
    Domain   : String;   { e.g. 'fidonet'; appended to M_ADR when set }
    SysName  : String;
    Sysop    : String;
    Location : String;
    Password : String;   { answering side: default session password }
    Timeout  : Integer;  { seconds }
    RequireCram : Boolean; { answering side: refuse cleartext passwords }
    NonReliable : Boolean; { ask the remote for NR mode (FTS-1028) }
    Compress    : Boolean; { offer PLZ dataframe compression (FTS-1029) }
  end;

function DefaultBinkConfig : TBinkConfig;

implementation

function DefaultBinkConfig : TBinkConfig;
begin
  Result := Default(TBinkConfig);
  Result.Timeout := BINK_DEFAULT_TIMEOUT;
end;

end.
