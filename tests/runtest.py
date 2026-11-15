#!/usr/bin/env python3
"""Phase 1 tests: the settings file (mkbink check) and the mailer (mkbink run) with two instances on localhost.
usage: tests/runtest.py [--slow]      (--slow also waits for a "poll 1" call, about 70 s)"""
import os, shutil, signal, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
slow = '--slow' in sys.argv
work = tempfile.mkdtemp(prefix='mkbt')
fails = 0
procs = []


def check(name, ok):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name)
    if not ok:
        fails += 1


def write(path, text, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(text)
    os.chmod(path, mode)


def run_check(text):
    p = os.path.join(work, 'chk.conf')
    write(p, text)
    r = subprocess.run([exe, 'check', '-f', p], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def wait(cond, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return cond()


class Node:
    def __init__(self, name, addr, port, links='', extra=''):
        self.name, self.addr, self.port = name, addr, port
        self.dir = os.path.join(work, name)
        self.conf = os.path.join(self.dir, 'links.conf')
        self.inb, self.out = self.dir + '/in', self.dir + '/out'
        self.logf = self.dir + '/log'
        self.text = lambda links=links: ('version 1\naddress %s\ninbound %s\nbso %s\nzone 1\nport %d\nbind 127.0.0.1\n'
                                         'retry-min 1\nretry-max 4\nscan-interval 1\n%s\n%s' % (addr, self.inb, self.out, port, extra, links))
        os.makedirs(self.inb, exist_ok=True)
        os.makedirs(self.out, exist_ok=True)
        write(self.conf, self.text())

    def start(self):
        self.log = open(self.logf, 'ab')
        self.p = subprocess.Popen([exe, 'run', '-f', self.conf], stdout=self.log, stderr=subprocess.STDOUT)
        procs.append(self.p)
        return wait(lambda: b'Mailer running' in self.logtext(), 5)

    def stop(self):
        self.p.send_signal(signal.SIGTERM)
        try:
            return self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            return -9

    def logtext(self):
        try:
            return open(self.logf, 'rb').read()
        except OSError:
            return b''

    def queue(self, to, path, flavour='N'):
        subprocess.run([exe, 'queue', '-O', self.out, '-Z', '1', '-t', to, '-F', flavour, '-x', path], check=True,
                       capture_output=True)


def blob(name, size=300000):
    p = os.path.join(work, name)
    with open(p, 'wb') as f:
        f.write(os.urandom(size))
    return p


try:
    # ---- the settings file
    rc, out = run_check('version 1\naddress 1:1/1\nlink 1:2/2\n  host h.example\n  password x\n')
    check('check: a small file is accepted', rc == 0 and 'ok: 1 link' in out)
    rc, out = run_check('address 1:1/1\n')
    check('check: no version line is an error', rc == 1 and 'line 1' in out and 'version' in out)
    rc, out = run_check('version 9\naddress 1:1/1\n')
    check('check: a newer version is an error', rc == 1 and 'newer' in out)
    rc, out = run_check('version 1\n')
    check('check: no address is an error', rc == 1 and 'no "address"' in out)
    rc, out = run_check('version 1\naddress 1:1/1\nport 99999\nlink 1:2\nlink 1:3/3\n port x\n poll\n')
    check('check: errors are listed with line numbers (%d lines)' % out.count('error:'),
          rc == 1 and 'line 3' in out and 'line 4' in out and 'line 6' in out and 'line 7' in out)
    rc, out = run_check('version 1\naddress 1:1/1\nfutureoption 3\nlink 1:2/2\n  colour blue\n')
    check('check: unknown keys are only warnings', rc == 0 and out.count('warning:') == 2)
    rc, out = run_check('version 1\naddress 1:1/1\nlink 1:2/2\nlink 1:2/2\n')
    check('check: a link listed twice is an error', rc == 1 and 'twice' in out)
    rc, out = run_check('version 1  # the format\naddress 1:1/1 # me\nlink 1:2/2 # hub\n  host 10.0.0.1 #x\n')
    check('check: comments after values', rc == 0 and '10.0.0.1:24554' in out)
    rc, out = run_check('version 1\naddress 1:1/1\naddress 1:1/2\nlink 1:2/2\n  us 1:1/2\n  plz yes\n  nr no\n  answer-only yes\n')
    check('check: AKAs, us, plz, nr, answer-only', rc == 0 and 'address 1:1/2' in out and 'answer-only yes' in out)

    # ---- two mailers: A calls B when mail waits; B answers
    pw = 'link %s\n  host 127.0.0.1\n  port %d\n  password secret\n'
    B = Node('b', '1:110/100', 24602, 'link 1:110/290\n  password secret\n  answer-only yes\n')
    A = Node('a', '1:110/290', 24601, pw % ('1:110/100', 24602))
    check('B starts and listens', B.start())
    f1 = blob('one.bin')
    want = open(f1, 'rb').read()
    A.queue('1:110/100', f1)
    check('A starts', A.start())
    delivered = os.path.join(B.inb, 'one.bin')
    check('mail waiting for B is called and delivered intact',
          wait(lambda: os.path.exists(delivered) and open(delivered, 'rb').read() == want, 20))
    check('... the call is logged', b'(mail waiting)' in A.logtext() and b'finished' in A.logtext())
    time.sleep(2.5)
    check('... and it is not called again with nothing left (one call)', A.logtext().count(b'Calling 1:110/100') == 1)

    # ---- hold mail does not trigger a call
    f2 = blob('hold.bin', 1000)
    A.queue('1:110/100', f2, 'H')
    time.sleep(3)
    check('hold mail does not start a call', A.logtext().count(b'Calling 1:110/100') == 1)

    # ---- B has mail for A: B is answer-only for A, so it never calls; A calls on its own schedule -> not here.
    # ---- an unknown system is refused
    C = Node('c', '1:110/777', 24603, 'link 1:110/290\n  host 127.0.0.1\n  port 24601\n  password secret\n')
    f3 = blob('three.bin', 5000)
    C.queue('1:110/290', f3)
    check('C starts', C.start())
    check('A answers C only if it is a known link: unknown system refused',
          wait(lambda: b'Rejected unknown address 1:110/777' in A.logtext(), 15))
    check('... C backs off and retries (retry in 1 s, then 2 s)',
          wait(lambda: b'retry in 1 s' in C.logtext() and b'retry in 2 s' in C.logtext(), 20))
    # reload: A learns about C
    write(A.conf, A.text(pw % ('1:110/100', 24602) + 'link 1:110/777\n  password secret\n  answer-only yes\n'))
    A.p.send_signal(signal.SIGHUP)
    check('A reloads the settings (2 links)', wait(lambda: b'Settings loaded: 2 link(s)' in A.logtext(), 5))
    check('... and C is now let in and delivers', wait(lambda: os.path.exists(os.path.join(A.inb, 'three.bin')), 25))
    check('C stops cleanly', C.stop() == 0)
    # reload with an error keeps the old settings
    write(A.conf, 'version 1\nport nonsense\n')
    A.p.send_signal(signal.SIGHUP)
    check('a reload with errors keeps the old settings', wait(lambda: b'old settings stay in use' in A.logtext(), 5))
    # reload that changes the port is only a note
    write(A.conf, A.text(pw % ('1:110/100', 24602)).replace('port 24601', 'port 24611'))
    A.p.send_signal(signal.SIGHUP)
    check('a changed port is reported as needing a restart', wait(lambda: b'used after a restart' in A.logtext(), 5))
    check('A stops cleanly (exit 0)', A.stop() == 0)
    check('B stops cleanly (exit 0)', B.stop() == 0)
    check('the settings file with passwords is not warned about (mode 600)', b'WARNING' not in A.logtext())

    # ---- file mode warning, bad settings, dead port
    D = Node('d', '1:110/888', 24604, 'link 1:110/1\n  host 127.0.0.1\n  port 24699\n  password x\n')
    os.chmod(D.conf, 0o644)
    D.queue('1:110/1', blob('dead.bin', 100))
    D.start()
    check('a world-readable settings file with passwords gets a warning', b'chmod 600' in D.logtext())
    check('a refused connection backs off 1, 2, 4, 4 seconds',
          wait(lambda: D.logtext().count(b'retry in 4 s') >= 2, 25) and b'retry in 1 s' in D.logtext() and b'retry in 2 s' in D.logtext())
    D.stop()
    write(os.path.join(work, 'bad.conf'), 'version 1\nport nonsense\n')
    r = subprocess.run([exe, 'run', '-f', os.path.join(work, 'bad.conf')], capture_output=True, text=True, timeout=10)
    check('run with a bad file exits 1 and says why', r.returncode == 1 and 'Settings error' in r.stdout)
    r = subprocess.run([exe, 'run', '-f', os.path.join(work, 'nothere.conf')], capture_output=True, text=True, timeout=10)
    check('run with a missing file exits 1', r.returncode == 1)
    # the port is taken -> fatal
    E1 = Node('e1', '1:110/5', 24605, '')
    E2 = Node('e2', '1:110/6', 24605, '')
    E1.start()
    E2.start()
    check('a port in use is fatal (exit 1)', wait(lambda: E2.p.poll() is not None, 10) and E2.p.returncode == 1)
    E1.stop()

    if slow:
        S1 = Node('s1', '1:110/21', 24606, '')
        S2 = Node('s2', '1:110/22', 24607, 'link 1:110/21\n  host 127.0.0.1\n  port 24606\n  password z\n  poll 1\n')
        write(S1.conf, S1.text('link 1:110/22\n  password z\n  answer-only yes\n'))
        S1.start()
        S2.start()
        check('slow: poll 1 calls the link at once, then after a minute',
              wait(lambda: S2.logtext().count(b'(scheduled)') >= 2, 80))
        S1.stop()
        S2.stop()
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(work, ignore_errors=True)

print('failures: %d' % fails)
sys.exit(1 if fails else 0)
