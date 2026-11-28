{ SPDX-License-Identifier: GPL-3.0-or-later }
program TestBink;

{$mode objfpc}{$H+}

{ Minimal example of using the library as an originating mailer:
  poll one system, send ./outbound, receive into ./inbound.
  For a full command line tool see mkbink.pas. }

uses
  SysUtils,
  BinkTypes,
  BinkNode,
  BinkInbound,
  BinkOutbound,
  BinkSession;

type
  TLogger = class
    procedure Print(const Msg : String);
  end;

procedure TLogger.Print(const Msg : String);
begin
  Writeln(Msg);
end;

var
  Config   : TBinkConfig;
  Node     : TBinkNodeInfo;
  Outbound : TBinkOutbound;
  Inbound  : TBinkInbound;
  Session  : TBinkSession;
  Logger   : TLogger;

begin
  Config := DefaultBinkConfig;
  Config.Address  := ParseAddress('1:110/290');
  Config.SysName  := 'MkBBS/FPC';
  Config.Sysop    := 'Mythical Kingdom BBS';

  Node := Default(TBinkNodeInfo);
  Node.Address  := ParseAddress('1:110/100');
  Node.Host     := '10.1.0.80';
  Node.Port     := BINK_DEFAULT_PORT;
  Node.Password := 'secret';

  Logger   := TLogger.Create;
  Outbound := TBinkOutbound.Create;
  Inbound  := TBinkInbound.Create('./inbound');
  Session  := TBinkSession.Create(Config);
  try
    Outbound.Scan('./outbound');

    Session.OnLog    := @Logger.Print;
    Session.Inbound  := Inbound;
    Session.Outbound := Outbound;

    if not Session.Originate(Node) then
      Halt(1);
  finally
    Session.Free;
    Inbound.Free;
    Outbound.Free;
    Logger.Free;
  end;
end.
