#!/usr/bin/env python3
"""The control socket of "mkbink run -S": hello, state frames, log lines, commands (POLL, HOLD, FREE, RESCAN, RELOAD, ABORT).
Two mailers on localhost; A calls B.   usage: controltest.py [--big MB]"""
import os, shutil, signal, socket, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
big = 192
if '--big' in sys.argv:
    big = int(sys.argv[sys.argv.index('--big') + 1])
work = tempfile.mkdtemp(prefix='mkct')
fails = 0
procs = []


def check(name, ok):
    global fails
    print(('ok   ' if ok else 'FAIL ') + 'control: ' + name)
    if not ok:
        fails += 1


def wait(cond, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'w').write(text)
    os.chmod(path, 0o600)


class Client:
    """a monitor: reads lines, keeps the last STATE frame and every LOG line"""

    def __init__(self, path):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.connect(path)
        self.s.settimeout(0.05)
        self.buf = b''
        self.lines = []          # everything received
        self.state = None        # last complete frame: list of lines
        self.cur = None
        self.frames = []         # all complete frames
        self.acks = []

    def pump(self):
        try:
            d = self.s.recv(65536)
            if d:
                self.buf += d
        except socket.timeout:
            pass
        while b'\n' in self.buf:
            line, self.buf = self.buf.split(b'\n', 1)
            t = line.decode('utf-8', 'replace')
            self.lines.append(t)
            if t.startswith('STATE '):
                self.cur = [t]
            elif self.cur is not None:
                self.cur.append(t)
                if t == 'END':
                    self.state = self.cur
                    self.frames.append(self.cur)
                    self.cur = None
            elif t.startswith(('ACK', 'ERR')):
                self.acks.append(t)

    def send(self, cmd):
        n = len(self.acks)
        self.s.sendall((cmd + '\n').encode())
        wait(lambda: (self.pump(), len(self.acks) > n)[1], 5)
        return self.acks[-1] if len(self.acks) > n else None

    def until(self, cond, secs=15):
        return wait(lambda: (self.pump(), cond(self))[1], secs)

    def rec(self, tag, frame=None):
        f = frame if frame is not None else self.state
        return [l[len(tag) + 1:].split('\t') for l in (f or []) if l.startswith(tag + ' ')]


def node(name, addr, port, links):
    d = os.path.join(work, name)
    for sub in ('in', 'out'):
        os.makedirs(os.path.join(d, sub), exist_ok=True)
    conf = os.path.join(d, 'links.conf')
    write(conf, 'version 1\naddress %s\nsysname Node %s\nsysop Op %s\ninbound %s/in\nbso %s/out\nzone 1\nport %d\nbind 127.0.0.1\n'
                'retry-min 1\nretry-max 4\nscan-interval 1\n%s' % (addr, name, name, d, d, port, links))
    return d, conf


def start(d, conf, sock):
    log = open(os.path.join(d, 'log'), 'ab')
    p = subprocess.Popen([exe, 'run', '-f', conf, '-S', sock], stdout=log, stderr=subprocess.STDOUT)
    procs.append(p)
    return p


def blob(name, mb):
    p = os.path.join(work, name)
    chunk = os.urandom(1024 * 1024)
    with open(p, 'wb') as f:
        for _ in range(mb):
            f.write(chunk)
    return p


try:
    bd, bconf = node('b', '1:110/100', 24702, 'link 1:110/290\n  password secret\n  answer-only yes\n')
    ad, aconf = node('a', '1:110/290', 24701, 'link 1:110/100\n  name Hub B\n  host 127.0.0.1\n  port 24702\n  password secret\n')
    # sockets go in a short directory (the path of a Unix socket is limited)
    sdir = tempfile.mkdtemp(prefix='s', dir='/tmp')
    asock, bsock = sdir + '/a.sock', sdir + '/b.sock'
    pb = start(bd, bconf, bsock)
    pa = start(ad, aconf, asock)
    check('both sockets appear (mode 600)', wait(lambda: os.path.exists(asock) and os.path.exists(bsock)) and
          oct(os.stat(asock).st_mode & 0o777) == '0o600')

    A = Client(asock)
    check('hello, then a state frame', A.until(lambda c: c.state is not None) and A.lines[0].startswith('HELLO MkBink'))
    me = A.rec('ME')[0]
    check('ME: our address, name, sysop, listen port, version', me[0] == '1:110/290' and me[1] == 'Node a' and me[2] == 'Op a' and me[4] == '24701')
    link = A.rec('LINK')[0]
    check('LINK: address, name, host:port, poll 0, idle, nothing waiting',
          link[0] == '1:110/100' and link[1] == 'Hub B' and link[2] == '127.0.0.1:24702' and link[4] == '0' and link[5] == 'idle' and link[9] == '0')
    check('STAT: nothing yet', A.rec('STAT')[0][:3] == ['0', '0', '0'])
    check('the log lines of the start are sent to a new client', any('Mailer running' in l for l in A.lines if l.startswith('LOG ')))

    # ---- commands
    check('PING', A.send('PING') == 'ACK pong')
    check('an unknown command is refused', (A.send('FROB') or '').startswith('ERR unknown'))
    check('POLL with a bad address', (A.send('POLL nonsense') or '').startswith('ERR "nonsense"'))
    check('POLL of a system that is no link', (A.send('POLL 1:5/5') or '').startswith('ERR 1:5/5 is not a link'))
    check('POLL * with no mail waiting', A.send('POLL *') == 'ERR no link has mail waiting')
    check('ABORT of a session that is not there', A.send('ABORT 99') == 'ERR no such session')
    check('RESCAN and RELOAD', (A.send('RESCAN') or '').startswith('ACK') and (A.send('RELOAD') or '').startswith('ACK'))

    # ---- hold, mail waiting, poll now
    check('HOLD', A.send('HOLD 1:110/100') == 'ACK 1:110/100 is held')
    f1 = blob('one.bin', 1)
    subprocess.run([exe, 'queue', '-O', ad + '/out', '-Z', '1', '-t', '1:110/100', '-x', f1], check=True, capture_output=True)
    check('mail waiting for a held link: shown (1 item, 1 MB), state held, flags H',
          A.until(lambda c: c.rec('LINK') and c.rec('LINK')[0][9] == '1' and c.rec('LINK')[0][5] == 'held') and
          A.rec('LINK')[0][3] == 'H' and int(A.rec('LINK')[0][10]) == 1024 * 1024)
    time.sleep(2.5)
    check('... and it is not called', not A.rec('SESS') and A.rec('STAT')[0][0] == '0')
    check('POLL while held: calls it anyway', A.send('POLL 1:110/100') == 'ACK calling 1:110/100')
    check('a session appears: outgoing, to 1:110/100', A.until(lambda c: any(f[1] == 'O' for f in c.rec('SESS'))) or
          any(any(f[1] == 'O' for f in A.rec('SESS', fr)) for fr in A.frames))
    check('... and ends: delivered, STAT counts the call, the bytes and the file',
          A.until(lambda c: not c.rec('SESS') and c.rec('STAT')[0][1] == '1') and A.rec('STAT')[0][:3] == ['1', '1', '0'] and
          int(A.rec('STAT')[0][4]) == 1024 * 1024 and A.rec('STAT')[0][6] == '1')
    check('... the file is in the inbound of B', os.path.exists(bd + '/in/one.bin') and os.path.getsize(bd + '/in/one.bin') == 1024 * 1024)
    check('LINK after the call: last call set, nothing waiting', A.until(lambda c: c.rec('LINK')[0][9] == '0') and A.rec('LINK')[0][11] != '0')
    check('FREE', A.send('FREE 1:110/100') == 'ACK 1:110/100 is released')
    check('the log carries the control commands', any('Control: POLL 1:110/100' in l for l in A.lines))

    # ---- the monitor of B sees the incoming session; a long transfer shows progress
    Bc = Client(bsock)
    Bc.until(lambda c: c.state is not None)
    f2 = blob('big.bin', big)
    subprocess.run([exe, 'queue', '-O', ad + '/out', '-Z', '1', '-t', '1:110/100', '-x', f2], check=True, capture_output=True)
    check('mail waiting: A calls B by itself (nothing held)', A.until(lambda c: any(f[1] == 'O' for f in c.rec('SESS'))))
    seen_tx = {}
    seen_in = []

    def watch(c):
        Bc.pump()
        for fr in A.frames[-20:]:
            for r in A.rec('SESS', fr):
                if r[13]:
                    seen_tx[r[13]] = max(seen_tx.get(r[13], 0), int(r[14]))
        for r in Bc.rec('SESS'):
            seen_in.append(r)
        return not c.rec('SESS') and A.rec('STAT')[0][1] == '2'

    A.until(watch, 120)
    if os.environ.get('DBG'):
        print('DBG frames', len(A.frames), 'with SESS', sum(1 for fr in A.frames if A.rec('SESS', fr)), 'seen_tx', seen_tx, 'seen_in', seen_in[:2])
        for fr in A.frames:
            for l in fr:
                if l.startswith('SESS'): print('DBG', repr(l)); break
    check('A showed the file being sent with a position, size %d MB' % big,
          'big.bin' in seen_tx and seen_tx['big.bin'] > 0)
    check('B showed an incoming session (I) with the remote address and the system name',
          any(r[1] == 'I' and '1:110/290' in r[2] and r[3] == 'Node a' for r in seen_in))
    check('B showed the file being received', any(r[16] == 'big.bin' and int(r[18]) == big * 1024 * 1024 for r in seen_in))
    check('the big file arrived intact', os.path.exists(bd + '/in/big.bin') and os.path.getsize(bd + '/in/big.bin') == big * 1024 * 1024)
    check('B counts the answered call', Bc.until(lambda c: c.rec('STAT')[0][3] == '2'))

    # ---- abort a session: queue again and cut it
    f3 = blob('cut.bin', max(big, 1024))
    subprocess.run([exe, 'queue', '-O', ad + '/out', '-Z', '1', '-t', '1:110/100', '-x', f3], check=True, capture_output=True)
    A.until(lambda c: any(f[1] == 'O' and f[7] == 'transfer' for f in c.rec('SESS')), 60)
    sess = [f for f in A.rec('SESS')]
    r = A.send('ABORT %s' % sess[0][0]) if sess else None
    check('ABORT ends a session that is running', r is not None and r.startswith('ACK') and A.until(lambda c: not c.rec('SESS')))
    check('... and counts as a failed call (retry wait follows)', A.until(lambda c: c.rec('STAT')[0][2] == '1') and A.until(lambda c: c.rec('LINK')[0][6] != '0' or c.rec('LINK')[0][5] in ('retry', 'calling')))

    # ---- a client that never reads does not stop the mailer; the socket goes with the mailer
    lazy = socket.socket(socket.AF_UNIX)
    lazy.connect(asock)
    time.sleep(1)
    check('a client that does not read: the mailer carries on', A.send('PING') == 'ACK pong')
    A.s.close()
    Bc.s.close()
    lazy.close()
    pa.send_signal(signal.SIGTERM)
    check('mailer stops cleanly, the socket file is gone', pa.wait(20) == 0 and not os.path.exists(asock))
    pb.send_signal(signal.SIGTERM)
    pb.wait(20)
    shutil.rmtree(sdir, ignore_errors=True)
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(work, ignore_errors=True)

print('failures: %d' % fails)
sys.exit(1 if fails else 0)
