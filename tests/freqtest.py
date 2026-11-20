#!/usr/bin/env python3
"""File requests, sending side (FTS-0006): mkbink queue -R writes the .req of a system, and a .req in the outbound is sent to it
(and removed when it has it).  Answering a request is not tested here.
usage: tests/freqtest.py"""
import os, shutil, signal, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
work = tempfile.mkdtemp(prefix='mkfq')
fails = 0
procs = []


def check(name, ok):
    global fails
    print(('ok   ' if ok else 'FAIL ') + 'freq: ' + name)
    if not ok:
        fails += 1


def wait(cond, secs=15):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return cond()


def rq(out, to, *args, zone='1'):
    return subprocess.run([exe, 'queue', '-O', out, '-Z', zone, '-t', to, '-R'] + list(args), capture_output=True, text=True)


class Node:
    def __init__(self, name, addr, port, links=''):
        self.dir = os.path.join(work, name)
        self.inb, self.out, self.logf = self.dir + '/in', self.dir + '/out', self.dir + '/log'
        self.conf = self.dir + '/links.conf'
        os.makedirs(self.inb)
        os.makedirs(self.out)
        with open(self.conf, 'w') as f:
            f.write('version 1\naddress %s\ninbound %s\nbso %s\nzone 1\nport %d\nbind 127.0.0.1\nretry-min 1\n'
                    'retry-max 4\nscan-interval 1\n%s' % (addr, self.inb, self.out, port, links))
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


try:
    o = os.path.join(work, 'o')
    r = rq(o, '1:12/2', 'this.arc', '!that', 'nodelist.*')
    f = os.path.join(o, '000c0002.req')
    check('requests are written to <net><node>.req in the outbound of the system', r.returncode == 0 and os.path.exists(f))
    check('... the spec format: name, a blank, !password, CR (LF after it); a name alone', open(f, 'rb').read() == b'this.arc !that\r\nnodelist.*\r\n')
    rq(o, '1:12/2', 'THIS.ARC', '!THAT', 'Nodelist.*', 'new.zip')
    check('a request that is waiting already is not written twice (names are not case sensitive)', open(f, 'rb').read() == b'this.arc !that\r\nnodelist.*\r\nnew.zip\r\n')
    rq(o, '1:12/2', 'this.arc', '!other')
    check('the same name with another password is another request', open(f, 'rb').read().endswith(b'this.arc !other\r\n'))
    check('another zone has its own directory (.zzz), a point its own (.pnt)',
          rq(o, '2:240/5', 'a.zip', zone='1').returncode == 0 and os.path.exists(o + '.002/00f00005.req')
          and rq(o, '1:12/2.7', 'p.zip').returncode == 0 and os.path.exists(o + '/000c0002.pnt/00000007.req'))
    n0 = open(f, 'rb').read()
    r = rq(o, '1:12/2', 'x.zip', '!1234567')
    check('a password of more than 6 characters is refused (nothing written)', r.returncode != 0 and '6 characters' in (r.stdout + r.stderr) and open(f, 'rb').read() == n0)
    check('a password of 6 characters is fine', rq(o, '1:12/2', 'y.zip', '!123456').returncode == 0)
    for bad in (['a b'], ['dir/x.zip'], ['a\\b'], ['!pw'], ['x.zip', '!']):
        r = rq(o, '1:12/2', *bad)
        check('refused: %r' % (bad,), r.returncode != 0 and open(f, 'rb').read().count(b'\n') == n0.count(b'\n') + 1)
    r = subprocess.run([exe, 'queue', '-O', o, '-Z', '1', '-t', '1:12/2', '-R'], capture_output=True, text=True)
    check('no name: refused', r.returncode != 0)

    # a .req in the outbound is sent: the mailer calls for it, the remote gets it, the outbound is empty after
    B = Node('b', '1:110/100', 24621, 'link 1:110/290\n  password secret\n  answer-only yes\n')
    A = Node('a', '1:110/290', 24622, 'link 1:110/100\n  host 127.0.0.1\n  port 24621\n  password secret\n')
    check('B starts', B.start())
    rq(A.out, '1:110/100', 'this.arc', '!that', 'nodelist.*')
    check('A starts', A.start())
    got = os.path.join(B.inb, '006e0122.req')          # named after the one who asked (110/290)
    check('the request arrives at the system asked, named with the net and node of the asker',
          wait(lambda: os.path.exists(got), 20) and open(got, 'rb').read() == b'this.arc !that\r\nnodelist.*\r\n')
    check('... and is removed from the outbound of the asker once the remote has it',
          wait(lambda: not os.path.exists(os.path.join(A.out, '006e0100.req')) and not os.path.exists(os.path.join(A.out, '006e0064.req')), 10))
    A.stop()
    B.stop()
    left = [x for x in os.listdir(A.out) if x.endswith('.req')]
    check('nothing is left in the outbound', not left)
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(work, ignore_errors=True)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
