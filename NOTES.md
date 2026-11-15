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
4. mkbink control socket (localhost, Unix) with structured events + commands (poll now, hold/release, rescan, reload);
   mkmon "Mailer" screen in the style of the old Frontdoor status screen.
5. Inbound hook (`--on-inbound`, a tosser plugs in here), secure / unsecure inbound split.
6. Nodelist lookup for links without a host (done in mkbinkcfg, so mkbink never touches the nodelist).
Later: tosser, netmail, file requests (config gives a "file request user" a level + flags like a caller's file access).

## Known gaps / edges

* `Authenticate` refuses the whole session if ANY address the remote presents is unknown to us.  A real mailer (binkd)
  presents all its AKAs, so a link block per AKA, or `accept-unknown`, is needed until this is relaxed to "at least one
  known".
* A local `.bsy` lock held by an answering session makes a call to that link fail (counted as a failure, backoff).
* Two callers receiving a file with identical name+size+time at once would share one `.part` file.
* No IPv6, no file requests (.req), no binkd GZ/CRYPT/ND/NDA/MB/EXTCMD.
