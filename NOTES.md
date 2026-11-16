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
   LOG lines as they happen.  Commands (answered by one ACK/ERR line): POLL <addr>|*, HOLD, FREE, RESCAN, RELOAD, ABORT <id>, PING
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
* No IPv6, no file requests (.req), no binkd GZ/ND/NDA/MB/EXTCMD.
* CRYPT has no setting in the links file (always on by default; `-E` on the command line disables it for poll/listen only).

## CRYPT (src/lib/binkcrypt.pas, commit 760c6fd)

Info-ZIP stream cipher as used by binkd and Synchronet.  Used automatically when the remote offers it, CRAM-MD5 was used, the password is real and the remote's `M_OK` says `secure` (a `non-secure` M_OK means the remote will not encrypt).  The originator sends `OPT CRYPT` before `M_PWD`; the answerer confirms with `OPT CRYPT` before `M_OK`.  `M_PWD` and `M_OK` are plaintext, everything after is encrypted, including frame headers.  Keys come from the password: originator->answerer stream = init(pw); answerer->originator = init("-") then pw bytes.
Verified: cipher matches an independent C implementation; real binkd 1.1a (poll + 3 MB send); Synchronet 3.19b (handshake and clean session end, no files moved); mkbink<->mkbink both directions.  Weak cipher: prefer TLS for real privacy.
