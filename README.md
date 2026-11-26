# mkbink

A binkp mailer for FidoNet style mail and files, written in Free Pascal (FTS-1026, 1027, 1028 and 1029; the texts are in `docs/`).  It answers calls and calls other systems, exchanges mail and files with them, and hands what it received to your tosser.
It is the mailer of the [MK BBS](https://github.com/mythicalkingdom/mkbbs) (`mklisten` starts it and `mkmon` shows it), but it knows nothing of that BBS: it is configured by one settings file ("links file") and works with any tosser that can be started as a command.

* **Two ways to call and answer**: poll one system and stop, answer calls only, or **run** as a mailer that does both: it calls a link when mail is waiting for it or when its poll time has come, retries a failed call with a back-off, and answers callers on its own port.
* **Passwords**: CRAM-MD5 or cleartext (`require-cram` refuses cleartext), and the CRYPT stream cipher that binkd and Synchronet use (a weak cipher: a tunnel is better for real privacy).  A system that is not a link is refused unless you say `accept-unknown`.
* **Mail and files in a spool you can read**: the BSO outbound (`.pkt`, flow files, `.req`, busy flags) or an **attach** (FrontDoor style) outbound of `*.msg` files; flavours crash, normal, hold; `^file` deletes and `#file` truncates after sending.
* **Compression and reliability**: PLZ, non-reliable mode, and **multiple batches** (also binkd's implicit ones), so that the answer to a file request goes out in the same session.
* **File requests (FTS-0006)**: it sends requests (`queue -R`) and answers them through a command you name: its own interface (`on-freq`) or an **SRIF** request processor (`on-freq-srif`, FSC-0086), with limits, hold mail for the answer, and the rule that a delete mark only ever removes a real file in its own temporary directory.
* **Hooks**: a command (no shell) after every session that received files (`on-inbound`: your tosser), with its own time limit.
* **IPv6**: calls try every address of a host name in turn, the listener takes IPv4 and IPv6 (`bind` limits it), `host` takes IPv6 literals.
* **Control socket**: a Unix socket for a monitor: the state of the sessions, links and log, and commands to poll a link, hold or free it, rescan, reload or abort a session.
* **Tested** against a real binkd 1.1a and Synchronet 3.19b, and by Python tests that run two mailers against each other on localhost.

## Build

Free Pascal 3.x and nothing else.

```
make                  build/mkbink (and the small example build/testbink)
make install          as root, or into a staging directory:  make install DESTDIR=/tmp/stage
```

The attach style needs the `MKMsg` units of the MK BBS (`../mk-fpc/src`, or `make MKMSG=dir`); without them mkbink is built without that style and says so.

## Use

```
mkbink poll host[:port] -a ADDR ...     one call, then exit (0 = completed)
mkbink listen -a ADDR ...               answer calls only
mkbink queue -O BSO -t ADDR file...     attach files to a link's outbound  (-R: file requests, -M -A: attach style)
mkbink run -f links.conf                the mailer: answer calls and call the links in the file
mkbink check -f links.conf              validate the settings file and show what it says
```

`run` is configured by the settings file only: your addresses, the directories (`inbound`, `bso` or `netmail` + `attach`), the port, the limits, the hooks, and a block for each link (its address, host, password, poll time).  The format is described in the comment at the top of
`src/lib/binklinks.pas`.  Send SIGHUP to read it again (links, passwords and timings apply to the next call), SIGTERM to stop; the log goes to standard output, one timestamped line for each event.  `run -S <socket>` makes the control socket.

With the MK BBS you do not write the file: `mkconfig` has the pages (EchoMail > Mailer, Mailer Links), `mkbinkcfg` makes the settings file from them and `mklisten` supervises the process.

## Tests

```
python3 tests/runtest.py [--slow]       settings file, calls both ways, IPv4 and IPv6
python3 tests/controltest.py            the control socket
python3 tests/batchtest.py  freqtest.py  hooktest.py  attachtest.py
```

## More

`NOTES.md` has the design notes: how `run` behaves, the integration with the MK BBS, CRYPT, attach style, file requests, SRIF, multiple batches, and the known gaps.  `src/lib/` holds the library units (`bink*.pas`), `src/app/` the programs.

## License

GPL-3.0-or-later, see [`LICENSE`](LICENSE).  Part of the Mythical Kingdom software.
