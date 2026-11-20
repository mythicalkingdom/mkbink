# mkbink notes

binkp mailer in Free Pascal (FTS-1026..1029).  `make` builds `build/mkbink`; `python3 tests/runtest.py [--slow]` runs the
settings-file and mailer tests (two instances on localhost).  Older protocol tests were done against a real binkd 1.1a
(see the project memory); they are not in `tests/`.

## Modes

    mkbink poll host[:port] -a ADDR ...     one call, then exit (0 = completed)
    mkbink listen -a ADDR ...               answer calls only
    mkbink queue -O BSO -t ADDR file...     attach files to a link's outbound
    mkbink run -f links.conf                the mailer: answer calls AND call the links in the file
    mkbink check -f links.conf              validate the file, show what it says

`run` is what the MK BBS uses (mklisten starts it).  It is configured only by the settings file ("links file", format in
the comment at the top of `src/lib/binklinks.pas`, version 1): mkbink knows nothing about the BBS.  The BBS side
generates that file from its own configuration (tool `mkbinkcfg`, in the mk-fpc repo, phase 2).

## Behaviour of `run` (src/lib/binkmailer.pas)

* Listener in a thread of its own; one thread per call made (max-polls, default 1).
* Every second the links are looked at: a call is made when mail is waiting in the BSO outbound (hold flavour does not
  count) or when the link's `poll N` minutes have passed.  Links with `answer-only yes` or no host are never called.
* A failed call is retried after retry-min seconds, doubled per failure up to retry-max.  After a successful call with
  mail still waiting, the next call is retry-min seconds later (so a remote that refuses files does not cause a loop).
* A system without a link block is refused unless `accept-unknown yes` (then with the global `password`).
* SIGTERM/SIGINT stop (cancel calls, join threads, exit 0); SIGHUP reads the file again: links, passwords, poll and retry
  settings apply to the next call / caller.  Addresses, paths, port, bind, session options are only used at start; a
  change is logged ("used after a restart").  A file with errors on reload leaves the old settings in use.
* Fatal (exit 1): bad settings at start, listener cannot bind.
* Warns if the file holds passwords and is readable by others.  Log goes to stdout, one timestamped line per event.

## Plan: integration with MK BBS (decided 2026-11-15)

Separate process, supervised by mklisten (`"mailer"` port type in mklisten.json).  Phases:

1. **mkbink reads a links file; `run`/`check` modes** - DONE (this repo).
2. **DONE** (mk-fpc repo): mailer settings in `Mailer.Mk` (new file, record `MailerCfgType` in `src/MKGlobT.pas`, 64 links, 1 KB expansion, reserved file-request fields), `mkconfig` pages EchoMail > Mailer / Mailer Links (`src/CfgMail.pas`), `mkbinkcfg` writes the links file (mode 0600, replaced all at once, untouched when nothing changed, exit 3 = mailer not enabled).  Own address(es), name, sysop, location come from Config.Mk; inbound and BSO directories are the EchoMail Options (EchoCfg.Mk), relative ones from the BBS directory.  The links file is the contract: mkbinkcfg must keep writing `version 1` until this repo's `BINK_LINKS_VERSION` changes.
3. **DONE** (mk-fpc repo): mklisten has a top-level `"mailer"` section (`config` = BBS config dir; optional `mkbink`, `mkbinkcfg`, `settings`, `logfile`, `interval`, `restart`).  It runs `mkbinkcfg -q -o <settings>` at the start, on SIGHUP and whenever Config.Mk / EchoCfg.Mk / Mailer.Mk changed (checked every `interval` s); exit 0 = mailer wanted, 3 = switched off (mkbink stopped), 1 = error (mkbink keeps running).  It starts `mkbink run -f <settings>` (prctl PDEATHSIG: dies with mklisten), sends it SIGHUP when the settings file changed, restarts it when it dies (delay `restart` s, doubled while it dies within 60 s, max 300) and stops it (SIGTERM, then SIGKILL after 15 s) when mklisten stops.  `make install` builds/installs mkbink from ../mkbink (MKBINK=...); the systemd unit has ExecReload (SIGHUP).  This repo's side needs nothing: mkbink only has to keep honouring SIGTERM (clean stop) and SIGHUP (reload).
4. **DONE**: `mkbink run -S <socket>` makes a Unix socket (mode 600; mklisten passes `<rundir>/mailer.sock`) that a monitor connects to.
   Text lines: HELLO, the last 200 LOG lines, then STATE ... END frames (ME, STAT, LINK, SESS lines, tab separated; layout in the
   comment above `BuildState` in `src/lib/binkmailer.pas`) every 250 ms during a session, otherwise on a change and every 5 s;
   LOG lines as they happen.  Commands (answered by one ACK/ERR line): POLL <addr>|*, HOLD, FREE, RESCAN, RELOAD, ABORT <id>, PING, REQ (below)
   (`src/lib/binkcontrol.pas`).  The session publishes its progress (`OnProgress`, `TBinkProgress`: remote names from M_NUL, bytes, files,
   file being sent / received with position) from its own thread.  mkmon (mk-fpc, `src/MKMonMail.pas`, key M in the node list) shows it in
   the style of the FrontDoor status screen.  `tests/controltest.py [--big MB]` tests the socket with two mailers.
5. **DONE**: settings keys `inbound-unsecure <dir>` (files from callers that did not authenticate with a password, i.e. `not Secure`; default = the same as `inbound`; session property `InboundUnsecure`, picked in `CurInbound`) and `on-inbound <command>` + `hook-timeout <s>` (default 300).  After every session (ours or theirs) that received files (`TBinkSession.Received` = full paths) the mailer runs the command in the session's thread (`TBinkMailer.RunHook`), without a shell, one at a time (FHookLock), with the file paths as arguments and MKBINK_REMOTE / _SECURE / _ORIG / _FILES in the environment; output goes into the log as `[hook] ...`; killed after the timeout.  The command is re-read on reload; the unsecure directory needs a restart (in `RestartKey`).  mk-fpc: fields carved out of `Mailer.Mk`'s expansion (UnsecureIn, OnInbound, HookTimeout), mkconfig page Mailer.  Sockets are now FD_CLOEXEC: a command we start no longer keeps the listen port open after mkbink stops.  `tests/hooktest.py`.
6. **DONE** (mk-fpc repo): `mkbinkcfg` gives a link that has no host one from the nodelist index (IBN / IBN:port / IBN:host[:port] / INA:host flags; needs IBN; link's own host/port win; answer-only links and points are skipped; note on stderr when there is no index).  mkbink never touches the nodelist; the settings file just says `host x   # from the nodelist`.  mklisten re-runs mkbinkcfg hourly.  `tests/nlhosttest.py` in mk-fpc.
Later: tosser, netmail, file requests (config gives a "file request user" a level + flags like a caller's file access).

## Known gaps / edges

* (fixed in phase 4) A remote that presents several addresses is accepted when at least one is known; the others are ignored.
* A local `.bsy` lock held by an answering session makes a call to that link fail (counted as a failure, backoff).
* Two callers receiving a file with identical name+size+time at once would share one `.part` file.
* No IPv6, no binkd GZ/ND/NDA/MB/EXTCMD.
* CRYPT has no setting in the links file (always on by default; `-E` on the command line disables it for poll/listen only).

## CRYPT (src/lib/binkcrypt.pas, commit 760c6fd)

Info-ZIP stream cipher as used by binkd and Synchronet.  Used automatically when the remote offers it, CRAM-MD5 was used, the password is real and the remote's `M_OK` says `secure` (a `non-secure` M_OK means the remote will not encrypt).  The originator sends `OPT CRYPT` before `M_PWD`; the answerer confirms with `OPT CRYPT` before `M_OK`.  `M_PWD` and `M_OK` are plaintext, everything after is encrypted, including frame headers.  Keys come from the password: originator->answerer stream = init(pw); answerer->originator = init("-") then pw bytes.
Verified: cipher matches an independent C implementation; real binkd 1.1a (poll + 3 MB send); Synchronet 3.19b (handshake and clean session end, no files moved); mkbink<->mkbink both directions.  Weak cipher: prefer TLS for real privacy.

## Attach (FrontDoor) style outbound (src/lib/binkattach.pas, binkpacket.pas, binkspool.pas)

An alternative to BSO, chosen with `-M <netmail dir> -A <attach dir>` (instead of `-O`) or `netmail`/`attach` instead of `bso` in the settings file.  Never run both styles on the same files.  `TBinkSpool` (binkspool.pas) is the neutral base class the session/mailer use; `TBinkBso` and `TBinkAttachSpool` implement it.  Items report completion through `TBinkOutItem.OnSent`/`Ref`.

* Mail = FTS-0001 `*.msg` files in the netmail directory, read and updated with `MKMsgFid` from the MK BBS (`../mk-fpc/src`, or `make MKMSG=dir`; without the units mkbink builds without this style and says so).  The units are not thread safe: all use is serialised in the spool.  Packets are written with `MKMsgPkt` (type 2+ header; it rebuilds INTL/FMPT/TOPT and adds a MSGID when the message has none; texts stay CP437).  mkbink has no packet code of its own.  A message the unit refuses (error 1012/1013 etc.) is skipped, stays in the netmail directory, and is logged ("Outbound: Netmail N ... not packed"); an empty From/To becomes Unknown/Sysop.
* A message goes to a link when its destination is the link, it is not marked Sent, not a file request, Crash first, then normal, then Hold (Hold for pickup, $0200, via IsHold/SetHold; sent only when the remote called us, in its own packet).
* **File Attach** message: only the file is sent, named by the subject: `^file` delete after, `#file` truncate, bare name looked up in `<attach>/<zone.net.node.point>/` then `<attach>/`.  **Other netmail**: all messages for the link and flavour go into one packet `<hex>.pkt` built in `<attach>/packets/<link>/` (leftovers of an interrupted session are swept on the next call).  Only the Private and Crash attribute bits go into the packet.
* After M_GOT: the message is marked Sent, or deleted if it has Kill/Sent.
* Lock: `<attach>/<link>.bsy` (same stale rules as BSO) plus an in-process set.
* `mkbink queue -M -A -a <us> -t <addr> [-F C|N|H] [-x] file` copies the file to `<attach>/<link>/` (moves it with -x, which also sets ^ and Kill/Sent) and writes a File Attach message (local, private, crash for C/I, Hold for H, D = N).  Immediate/direct do not exist here.
* Not verified against a real FrontDoor spool (none available): the attach-file naming is our own scheme, and FrontDoor's own flags (hold/direct bits are only read as Hold) were not checked.  `tests/attachtest.py` writes the `*.msg` files and parses the packets independently (python), including `run -f` mode.
* Gaps: message text goes into the packet unchanged (INTL/FMPT/TOPT must already be in it, which MKMsgFid and `queue` do); `.msg` paths are limited to 110 characters by MKMsgFid; no routing (only messages addressed to the link itself).

* mk-fpc's tosser (`mktoss`) is the `on-inbound` command when the sysop switches it on (mkbinkcfg writes the line); mklisten starts mkbink with `MK=<BBS config dir>` in its environment because the hook needs it.  Verified end to end by mk-fpc's `tests/tosshooktest.py`.

* `mkbink queue -T` truncates the file after it was sent (flow line `#file`), `-x` deletes it (`^file`); mk-fpc's tosser uses both for file attach netmail.

## File requests (FTS-0006; plan in mk-fpc `FREQ-PLAN.md`)

* **Sending** (`binkbso.pas`): `mkbink queue -O DIR -t ADDR -R name [!password] [+time|-time] ...` adds lines `name !password +time` (CR LF,
  password at most 6 characters, the time an update request: a sign and at most 10 digits, UNIX seconds, `-time` is not an option after
  `-R`; the whole list is checked before any of it is written; no duplicates) to the system's `<net><node>.req` in the BSO outbound.  A non-empty `.req` counts as normal mail (the
  mailer calls for it), is sent as `<our net><our node>.req`, and is deleted when the remote has it (M_GOT).
* **Answering** (`binkmailer.pas`, `DoFreq`): settings `freq yes|no` (default no: a .req is then an ordinary file), `freq-unsecure
  yes|no` (callers without a password; default no: the request is ignored and removed), `on-freq <command>`, `freq-max-files` (20),
  `freq-max-kb` (0 = no limit).  After a session that received `*.req` files (and not given to `on-inbound`), the command is run, one at
  a time and killed after `hook-timeout`, with `<requester> <secure|unsecure> <request file> <answer file>` and `MKBINK_REMOTE`,
  `MKBINK_SECURE`, `MKBINK_ORIG` in the environment.  It writes the answer file: tab separated lines `SEND<TAB>/absolute/path`
  (`<TAB>^` = delete it after it was sent) and `NOTE<TAB>text` (logged).  The files are queued for the requester as **hold mail** (flavour H,
  `TBinkSpool.Attach`: sent when the requester calls us to pick them up; our mailer does not call it for them) within the limits, which mkbink keeps as well as the command; the request and answer files are removed.
  `tests/freqtest.py` (29 checks) uses a stub command.
* **In the same session** when both sides offer multiple batches (below): `BatchEnded` (the session's `OnBatchEnd`) answers the
  requests received so far, the answer is collected again and goes in the next batch.  Hold mail is only sent to a system that called us,
  so a requester we called gets it at its next call; so does one that does not offer multiple batches (`multi-batch no` on either side).

## Multiple batches (OPT MB; `binksession.pas`)

* Both sides put ` MB` in their `M_NUL OPT` line (settings key `multi-batch yes|no`, default yes) and use it when both did; otherwise a
  session has one batch as before (FTS-1026 only knows one).
* Each side counts the `M_FILE` frames of the batch, sent and received (the same number at both ends).  When the batch is over (both
  `M_EOB`, nothing pending) and the count is not 0, another batch follows; a batch in which no file moved ends the session.
* `NextBatch`: calls `OnBatchEnd`, collects the outbound again (without locking again; hold mail only when the remote called us), leaves out
  what this session offered already (`FDone`, so a file the remote refused is not offered again and again), resets the transmit and
  receive state.  The end of a batch is checked after every frame, so a frame of the next batch is never taken for the old one.
* Tested with two mkbink and a stub command (`tests/freqtest.py`) and in `mk-fpc` (`tests/freqroundtrip.py`); not tried against binkd (it
  has an `MB` option too, which we assume means the same).

## File requests from the control socket (REQ)

`REQ <addr> <host[:port]|-> <session password|-> <0|1> <name [!pw] [+time|-time]>[|<more>...]` (binkmailer.pas, `HandleRequest`): the
requests are checked as a whole (`CheckRequest`), written to the `.req` of the address (`Request`), and with 1 the system is called at once.
`-` as host uses the host of the link (`Force`); a host given is called as it is, with no entry in the links file needed (a temporary
`TBinkLink`; the password is the one given, else the link's when the host is the link's, else none = an unsecure session); our AKA and the
Plz/Nr settings come from the link when there is one.  A system that is no link and that answers only callers it knows ("Bad address") must be told: `accept-unknown yes` lets strangers call (with the
global `password`, or none: an unsecure session; `freq-unsecure yes` then answers their requests, the classic anonymous file request;
`freqtest.py` and `controltest.py` cover it).
mkmon's mailer screen has the F key for this (dialog: address, host, session password, files, call now).  The host is looked up by the
monitor, not by mkbink: with the host left empty, a system that is no link, or a link with no host, is found in the nodelist index of the BBS
(`MKNodeHost.pas` in mk-fpc, the same lookup mkbinkcfg uses: IBN / INA flags; all the nodelists of `mknodeidx` are searched, zone numbers pick
the list; no domain).  `tests/controltest.py`, mk-fpc `tests/mailmontest.py`.
