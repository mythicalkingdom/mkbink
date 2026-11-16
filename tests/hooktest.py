#!/usr/bin/env python3
"""Phase 5: files from a caller without a password go to inbound-unsecure, and on-inbound runs after a session that
received files (arguments = the files, environment MKBINK_*), one at a time, killed after hook-timeout.
usage: tests/hooktest.py"""
import os, shutil, signal, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
work = tempfile.mkdtemp(prefix='mkhk')
fails = 0
procs = []


def check(name, ok):
    global fails
    print(('ok   ' if ok else 'FAIL ') + 'hook: ' + name)
    if not ok:
        fails += 1


def wait(cond, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return cond()


class Node:
    def __init__(self, name, addr, port, links='', extra=''):
        self.dir = os.path.join(work, name)
        self.inb, self.out, self.logf = self.dir + '/in', self.dir + '/out', self.dir + '/log'
        self.conf = self.dir + '/links.conf'
        os.makedirs(self.inb)
        os.makedirs(self.out)
        with open(self.conf, 'w') as f:
            f.write('version 1\naddress %s\ninbound %s\nbso %s\nzone 1\nport %d\nbind 127.0.0.1\nretry-min 1\n'
                    'retry-max 4\nscan-interval 1\n%s\n%s' % (addr, self.inb, self.out, port, extra, links))
        os.chmod(self.conf, 0o600)

    def start(self):
        self.p = subprocess.Popen([exe, 'run', '-f', self.conf], stdout=open(self.logf, 'ab'), stderr=subprocess.STDOUT)
        procs.append(self.p)
        return wait(lambda: b'Mailer running' in self.log(), 5)

    def log(self):
        try:
            return open(self.logf, 'rb').read()
        except OSError:
            return b''

    def stop(self):
        self.p.send_signal(signal.SIGTERM)
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()

    def queue(self, to, path):
        subprocess.run([exe, 'queue', '-O', self.out, '-Z', '1', '-t', to, '-x', path], check=True, capture_output=True)


def blob(name, size):
    p = os.path.join(work, name)
    open(p, 'wb').write(os.urandom(size))
    return p


try:
    seen = os.path.join(work, 'seen')
    script = os.path.join(work, 'toss.sh')
    open(script, 'w').write('#!/bin/sh\n{ echo "START $MKBINK_REMOTE secure=$MKBINK_SECURE orig=$MKBINK_ORIG n=$MKBINK_FILES"; '
                            'for f in "$@"; do echo "FILE $f"; done; sleep 1; echo END; } >> %s; echo "some output"\n' % seen)
    os.chmod(script, 0o755)
    unsec = os.path.join(work, 'unsecure')
    # B has two links: one with a password, one that may call without
    B = Node('b', '1:110/100', 24612,
             'link 1:110/290\n  password secret\n  answer-only yes\n',
             'inbound-unsecure %s\non-inbound %s -v\nhook-timeout 30\naccept-unknown yes\n' % (unsec, script))
    A = Node('a', '1:110/290', 24611, 'link 1:110/100\n  host 127.0.0.1\n  port 24612\n  password secret\n')
    check('B starts', B.start())
    f1 = blob('one.bin', 50000)
    A.queue('1:110/100', f1)
    check('A starts', A.start())
    got = os.path.join(B.inb, 'one.bin')
    check('a caller with a password: the file is in the normal inbound', wait(lambda: os.path.exists(got), 20))
    check('... the command ran with the file path, the remote and secure=1',
          wait(lambda: os.path.exists(seen) and 'END' in open(seen).read(), 10)
          and ('FILE ' + got) in open(seen).read() and 'START 1:110/290' in open(seen).read()
          and 'secure=1 orig=0 n=1' in open(seen).read())
    check('... its output is in the log', wait(lambda: b'[hook] some output' in B.log() and b'[hook] done' in B.log(), 5))
    check('... and nothing went to the unsecure directory', not os.path.exists(unsec) or not os.listdir(unsec))
    A.stop()

    # a caller without a password (a system without a link, accept-unknown with no password)
    open(seen, 'w').close()
    D = Node('d', '1:110/555', 24613, 'link 1:110/100\n  host 127.0.0.1\n  port 24612\n')
    f2 = blob('two.bin', 4000)
    D.queue('1:110/100', f2)
    check('D starts', D.start())
    got2 = os.path.join(unsec, 'two.bin')
    check('a caller without a password: the file is in inbound-unsecure', wait(lambda: os.path.exists(got2), 20))
    check('... not in the normal inbound', not os.path.exists(os.path.join(B.inb, 'two.bin')))
    check('... the command got that path and secure=0',
          wait(lambda: 'END' in open(seen).read(), 10) and ('FILE ' + got2) in open(seen).read() and 'secure=0' in open(seen).read())
    D.stop()
    B.stop()

    # the command is killed after hook-timeout
    open(seen, 'w').close()
    slow = os.path.join(work, 'slow.sh')
    open(slow, 'w').write('#!/bin/sh\nsleep 30\n')
    os.chmod(slow, 0o755)
    E = Node('e', '1:110/101', 24614, 'link 1:110/291\n  password s\n  answer-only yes\n', 'on-inbound %s\nhook-timeout 1\n' % slow)
    F = Node('f', '1:110/291', 24615, 'link 1:110/101\n  host 127.0.0.1\n  port 24614\n  password s\n')
    E.start()
    F.queue('1:110/101', blob('three.bin', 1000))
    F.start()
    t0 = time.time()
    check('a command that runs too long is killed (hook-timeout 1)', wait(lambda: b'killed after 1 s' in E.log(), 15) and time.time() - t0 < 14)
    F.stop()
    E.stop()

    # a missing command is logged, the mailer carries on
    G = Node('g', '1:110/102', 24616, 'link 1:110/292\n  password s\n  answer-only yes\n', 'on-inbound /nonexistent/tosser\n')
    H = Node('h', '1:110/292', 24617, 'link 1:110/102\n  host 127.0.0.1\n  port 24616\n  password s\n')
    G.start()
    H.queue('1:110/102', blob('four.bin', 1000))
    H.start()
    check('a command that does not exist is logged and the mailer keeps running',
          wait(lambda: b'[hook] cannot run' in G.log(), 15) and G.p.poll() is None)
    H.stop()
    G.stop()

    rc, out = 0, ''
    r = subprocess.run([exe, 'check', '-f', B.conf], capture_output=True, text=True)
    check('mkbink check accepts the keys', r.returncode == 0 and 'warning' not in (r.stdout + r.stderr))
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(work, ignore_errors=True)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
