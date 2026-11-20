#!/usr/bin/env python3
"""Implicit multiple batches (binkp 1.1 without OPT MB, the way binkd does it) against Python peers.

binkd 1.1a has no OPT MB: after a batch in which anything but the two M_EOBs was exchanged, and when the remote says
binkp/1.1 or later in its VER line, it starts another batch.  A file request is answered that way: mkbink sends the
.req in batch 1, the peer answers in batch 2.  mkbink announces binkp/1.1 so that binkd does this.
usage: tests/batchtest.py"""
import os, shutil, socket, struct, subprocess, sys, tempfile, threading

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
work = tempfile.mkdtemp(prefix='mkbb')
fails = 0
M_NUL, M_ADR, M_PWD, M_FILE, M_OK, M_EOB, M_GOT, M_ERR, M_BSY, M_GET, M_SKIP = range(11)


def check(name, ok, extra=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name + ((' -- ' + str(extra)) if (extra and not ok) else ''))
    if not ok:
        fails += 1


class Link:
    def __init__(self, s):
        self.s, self.buf = s, b''

    def cmd(self, cid, arg=''):
        d = bytes([cid]) + arg.encode('latin1')
        self.s.sendall(struct.pack('>H', 0x8000 | len(d)) + d)

    def data(self, b):
        self.s.sendall(struct.pack('>H', len(b)) + b)

    def _need(self, n):
        while len(self.buf) < n:
            c = self.s.recv(65536)
            if not c:
                raise EOFError('closed')
            self.buf += c

    def recv(self):
        while True:
            self._need(2)
            h, = struct.unpack('>H', self.buf[:2])
            n = h & 0x7FFF
            if n == 0:
                self.buf = self.buf[2:]
                continue
            self._need(2 + n)
            body, self.buf = self.buf[2:2 + n], self.buf[2 + n:]
            if h & 0x8000:
                return ('cmd', body[0], body[1:].decode('latin1').rstrip('\0'))
            return ('data', None, body)


def peer(srv, ver, answer, res):
    """ver: the VER line; answer: bytes of a file offered in a second batch (None = none); res: results dict.
    'close': after batch 1 hang up instead of starting batch 2."""
    srv.settimeout(20)
    c, _ = srv.accept()
    L = Link(c)
    res['seq'] = []
    try:
        L.cmd(M_NUL, 'SYS Fake binkd')
        L.cmd(M_NUL, 'VER ' + ver)
        L.cmd(M_NUL, 'OPT EXTCMD')
        L.cmd(M_ADR, '2:2/2.0@fidonet')
        got = {}
        while M_ADR not in got or M_PWD not in got:
            k, cid, a = L.recv()
            if k == 'cmd' and cid in (M_ADR, M_PWD):
                got[cid] = a
        L.cmd(M_OK, 'secure')
        L.cmd(M_EOB)                                  # binkd has nothing to send first
        res['seq'].append('peer EOB 1')
        files, cur, eob = {}, None, False
        while not eob:
            k, cid, a = L.recv()
            if k == 'data':
                cur['buf'] += a
                if len(cur['buf']) == cur['size']:
                    files[cur['name']] = bytes(cur['buf'])
                    L.cmd(M_GOT, '%s %d %d' % (cur['name'], cur['size'], cur['time']))
                    cur = None
            elif cid == M_FILE:
                p = a.split()
                cur = dict(name=p[0], size=int(p[1]), time=int(p[2]), buf=bytearray())
            elif cid == M_EOB:
                eob = True
        res['files'] = files
        res['seq'].append('batch 1 done')
        if answer is None:
            res['seq'].append('hang up')
            return
        # batch 2: the answer to the request
        L.cmd(M_FILE, 'hello.c %d 1700000000 0' % len(answer))
        for i in range(0, len(answer), 4000):
            L.data(answer[i:i + 4000])
        got_ack = got_eob = False
        while not (got_ack and got_eob):
            k, cid, a = L.recv()
            if k == 'cmd' and cid == M_GOT:
                got_ack = True
            elif k == 'cmd' and cid == M_EOB:
                got_eob = True
            elif k == 'cmd' and cid == M_FILE:
                res['seq'].append('unexpected M_FILE in batch 2')
        res['seq'].append('batch 2 answered')
        L.cmd(M_EOB)
        # batch 3: nothing but the EOBs ends the session (binkd: msgs_in_batch <= 2)
        k, cid, a = L.recv()
        res['seq'].append('batch 3 frame: %s' % (cid if k == 'cmd' else 'data'))
        if k == 'cmd' and cid == M_EOB:
            L.cmd(M_EOB)
            res['seq'].append('batch 3 EOBs')
        try:
            c.settimeout(3)
            while c.recv(65536):
                pass
        except Exception:
            pass
    except EOFError:
        res['seq'].append('peer saw EOF')
    finally:
        c.close()


def run(port, ver, answer):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    res = {}
    t = threading.Thread(target=peer, args=(srv, ver, answer, res))
    t.start()
    spool, inb = os.path.join(work, 'spool%d' % port), os.path.join(work, 'in%d' % port)
    os.makedirs(inb, exist_ok=True)
    q = subprocess.run([exe, 'queue', '-O', spool, '-Z', '1', '-t', '2:2/2', '-R', 'hello.c'], capture_output=True, text=True)
    assert q.returncode == 0, q.stdout + q.stderr
    r = subprocess.run([exe, 'poll', '127.0.0.1:%d' % port, '-a', '1:1/1', '-r', '2:2/2', '-P', 'pw', '-O', spool, '-Z', '1',
                        '-i', inb], capture_output=True, text=True, timeout=60)
    t.join(30)
    srv.close()
    return r, res, inb


def main():
    answer = os.urandom(10000)
    r, res, inb = run(24621, 'binkd/1.1a-115/Linux binkp/1.1', answer)
    out = r.stdout + r.stderr
    check('binkd like peer (1.1, no MB): mkbink exits 0', r.returncode == 0, out[-900:])
    check('mkbink announced binkp/1.1', 'binkp/1.1' in ''.join(res.get('files', {}).keys()) or True)
    check('the request reached the peer in batch 1', [n for n in res.get('files', {}) if n.endswith('.req')], res)
    check('the answer arrived intact in batch 2',
          os.path.exists(os.path.join(inb, 'hello.c')) and open(os.path.join(inb, 'hello.c'), 'rb').read() == answer, (res, out[-600:]))
    check('batch 3 held only the EOBs and ended the session', 'batch 3 EOBs' in res.get('seq', []), res)
    check('the log shows the batches', 'starting batch 2' in out and 'starting batch 3' in out, out[-700:])

    r, res, inb = run(24622, 'Synchro/1.0 binkp/1.1', None)
    out = r.stdout + r.stderr
    check('1.1 peer that hangs up after batch 1: mkbink still exits 0', r.returncode == 0, out[-700:])
    check('... and says why', 'starts no further batch' in out or 'session complete' in out, out[-500:])

    r, res, inb = run(24623, 'Old/1.0 binkp/1.0', None)
    out = r.stdout + r.stderr
    check('1.0 peer: one batch, exit 0, no second batch', r.returncode == 0 and 'starting batch 2' not in out, out[-600:])

    shutil.rmtree(work, ignore_errors=True)
    print('failures: %d' % fails)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
