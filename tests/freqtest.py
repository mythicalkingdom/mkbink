#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""File requests (FTS-0006).  Sending side: mkbink queue -R writes the .req of a system, and a .req in the outbound is sent to it
(and removed when it has it).  Receiving side: a .req that arrives is answered by the command of on-freq (freq yes), the files it
names are queued for the requester and sent; limits, unsecure callers, a failing command.
usage: tests/freqtest.py"""
import os, shutil, signal, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
work = tempfile.mkdtemp(prefix='mkfq')
fails = 0
procs = []


def check(name, ok, info=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + 'freq: ' + name + ('' if ok else '  ' + str(info)))
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


STUB = '''#!/usr/bin/env python3
import os, sys
who, mode, req, ans = sys.argv[1:5]
open(CALLED, 'a').write('%s %s %s\\n' % (who, mode, os.environ.get('MKBINK_SECURE')))
if os.environ.get('STUB_FAIL'):
    sys.exit(1)
out = []
for line in open(req, 'rb').read().decode().split('\\n'):
    line = line.strip()
    if not line:
        continue
    name, _, pw = line.partition(' !')
    if name == 'this.arc' and pw != 'that':
        out.append('NOTE\\tthis.arc needs the right password')
    elif name == 'this.arc':
        out.append('SEND\\tFILES/this.arc')
    elif name == 'nodelist.*':
        out.append('SEND\\tFILES/nodelist.001')
        out.append('SEND\\tFILES/nodelist.002\\t^')
    else:
        out.append('NOTE\\t%s not found' % name)
out.append('SEND\\t/nonexistent/x.zip')
open(ans, 'w').write('\\n'.join(out) + '\\n')
print('stub answered', len(out))
'''


SRIF_STUB = '''#!/usr/bin/env python3
import os, shutil, sys
srif = open(sys.argv[1]).read()
open(COPYPATH, 'w').write(srif)
d = dict(l.split(' ', 1) for l in srif.split('\\n') if ' ' in l)
req, rsp = d['RequestList'].strip(), d['ResponseList'].strip()
tmp = os.environ['MKBINK_TMP']
out = []
for line in open(req, 'rb').read().decode().split('\\n'):
    name = line.strip().split(' ')[0]
    if name == 'keep.txt':
        out.append('+FILES/keep.txt')
    elif name == 'erase.txt':
        out.append('=FILES/erase.txt')
    elif name == 'minus.txt':
        out.append('-FILES/minus.txt')
    elif name == 'plain.txt':
        out.append('FILES/plain.txt')
    elif name == 'made.lst':
        open(os.path.join(tmp, 'made.lst'), 'w').write('made by the command')
        out.append('=' + os.path.join(tmp, 'made.lst'))
    elif name == 'lnk.txt':
        os.symlink('FILES/keep.txt', os.path.join(tmp, 'lnk.txt'))
        out.append('=' + os.path.join(tmp, 'lnk.txt'))
open(rsp, 'w').write('\\n'.join(out) + '\\n')
'''

NAT_STUB = '''#!/usr/bin/env python3
import os, sys
who, mode, req, ans = sys.argv[1:5]
tmp = os.environ['MKBINK_TMP']
out = []
for line in open(req, 'rb').read().decode().split('\\n'):
    name = line.strip().split(' ')[0]
    if name == 'natdel.txt':
        out.append('SEND\\tFILES/natdel.txt\\t^')
    elif name == 'made2.lst':
        open(os.path.join(tmp, 'made2.lst'), 'w').write('made')
        out.append('SEND\\t' + os.path.join(tmp, 'made2.lst') + '\\t^')
open(ans, 'w').write('\\n'.join(out) + '\\n')
'''


class Node:
    def __init__(self, name, addr, port, links='', extra=''):
        self.dir = os.path.join(work, name)
        self.inb, self.out, self.logf = self.dir + '/in', self.dir + '/out', self.dir + '/log'
        self.conf = self.dir + '/links.conf'
        os.makedirs(self.inb)
        os.makedirs(self.out)
        with open(self.conf, 'w') as f:
            f.write('version 1\naddress %s\ninbound %s\nbso %s\nzone 1\nport %d\nbind 127.0.0.1\nretry-min 1\n'
                    'retry-max 4\nscan-interval 1\n%s%s' % (addr, self.inb, self.out, port, extra, links))
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
    # update requests: a sign and a UNIX time after the name (and the password)
    u = os.path.join(work, 'u')
    r = rq(u, '1:12/2', 'NEWOPUS.*', '+599634000', 'this.arc', '!that', '-599634000', 'old.zip', '+5')
    fu = os.path.join(u, '000c0002.req')
    check('update requests: name +time, name !password -time (the order of the spec: password, then the time)',
          r.returncode == 0 and open(fu, 'rb').read() == b'NEWOPUS.* +599634000\r\nthis.arc !that -599634000\r\nold.zip +5\r\n')
    rq(u, '1:12/2', 'newopus.*', '+599634000')
    check('the same name with the same time is not written twice; another time is another request',
          open(fu, 'rb').read().lower().count(b'newopus') == 1 and rq(u, '1:12/2', 'newopus.*', '+599634001').returncode == 0
          and open(fu, 'rb').read().lower().count(b'newopus') == 2)
    n1 = open(fu, 'rb').read()
    for bad in (['+599634000'], ['-5'], ['x.zip', '+5', '!pw'], ['x.zip', '+'], ['x.zip', '+12a']):
        r = rq(u, '1:12/2', *bad)
        check('refused: %r' % (bad,), r.returncode != 0 and open(fu, 'rb').read() == n1)
    r = subprocess.run([exe, 'queue', '-O', u, '-Z', '1', '-t', '1:12/2', '-R', 'z.zip', '+12345678901'], capture_output=True, text=True)
    check('a time of more than 10 digits is refused', r.returncode != 0 and open(fu, 'rb').read() == n1)
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
    # ---- the receiving side: a stub command in place of mkfreq
    files = os.path.join(work, 'files')
    os.makedirs(files)
    for n, d in (('this.arc', b'ARC data'), ('nodelist.001', b'nodelist one'), ('nodelist.002', b'nodelist two')):
        open(os.path.join(files, n), 'wb').write(d)
    called = os.path.join(work, 'called')
    stub = os.path.join(work, 'stub.py')
    open(stub, 'w').write(STUB.replace('CALLED', repr(called)).replace('FILES', files))
    os.chmod(stub, 0o755)
    seen = os.path.join(work, 'seen')
    onin = os.path.join(work, 'onin.sh')
    open(onin, 'w').write('#!/bin/sh\\necho "$@" >> %s\\n' % seen)
    os.chmod(onin, 0o755)

    # B answers (freq yes, two files at most), A asks; the answer goes in a second batch of the session
    B2 = Node('b2', '1:110/101', 24631, 'link 1:110/291\n  host 127.0.0.1\n  port 24632\n  password secret\n',
              'freq yes\non-freq %s\nfreq-max-files 2\non-inbound %s\n' % (stub, onin))
    A2 = Node('a2', '1:110/291', 24632, 'link 1:110/101\n  host 127.0.0.1\n  port 24631\n  password secret\n')
    check('B2 starts', B2.start())
    rq(A2.out, '1:110/101', 'this.arc', '!that', 'nodelist.*', 'nothere.zip')
    check('A2 starts', A2.start())
    ga, gb = os.path.join(A2.inb, 'this.arc'), os.path.join(A2.inb, 'nodelist.001')
    check('the request is answered: the command ran and the files were queued', wait(lambda: b'2 file(s) queued' in B2.log(), 30))
    check('both sides offered multiple batches: the answer goes in the next batch of the SAME session (the asker did not call again)',
          wait(lambda: os.path.exists(ga) and os.path.exists(gb), 30) and open(ga, 'rb').read() == b'ARC data' and open(gb, 'rb').read() == b'nodelist one'
          and b'starting batch 2' in B2.log() and b'starting batch 2' in A2.log())
    check('... the request was answered at the end of the batch that brought it, before the session ended',
          B2.log().find(b'file(s) queued') < B2.log().find(b'session complete') and b'1 call' not in B2.log())
    lg = B2.log().decode('latin-1')
    check('... the command got the requester, secure, the request and the answer file',
          wait(lambda: os.path.exists(called), 5) and open(called).read().split('\n')[0] == '1:110/291 secure 1')
    check('... a NOTE of the command is in the log, a file that does not exist is not sent',
          'not found' in lg and 'not an existing file with an absolute path: /nonexistent/x.zip' in lg)
    check('... the limit of 2 files holds: the third is not sent, and is not deleted (^ is only after it was sent)',
          'nodelist.002 not sent, over the limit of 2 files' in lg and not os.path.exists(os.path.join(A2.inb, 'nodelist.002'))
          and os.path.exists(os.path.join(files, 'nodelist.002')))
    check('... the request file is not left in the inbound and is not given to on-inbound',
          not [f for f in os.listdir(B2.inb) if f.endswith(('.req', '.ans'))] and not os.path.exists(seen))
    check('... counted in the log', 'File request from 1:110/291' in lg and ': 2 file(s) queued' in lg)
    A2.stop()
    B2.stop()

    # no multiple batches (B6 does not offer them): the answer is hold mail and waits for the asker's next call
    B6 = Node('b6', '1:110/106', 24639, 'link 1:110/296\n  host 127.0.0.1\n  port 24640\n  password secret\n',
              'freq yes\non-freq %s\nfreq-max-files 2\nmulti-batch no\n' % stub)
    A6 = Node('a6', '1:110/296', 24640, 'link 1:110/106\n  host 127.0.0.1\n  port 24639\n  password secret\n')
    B6.start()
    rq(A6.out, '1:110/106', 'this.arc', '!that', 'nodelist.*')
    A6.start()
    ga6, gb6 = os.path.join(A6.inb, 'this.arc'), os.path.join(A6.inb, 'nodelist.001')
    check('without multiple batches: the request is answered and the files are queued', wait(lambda: b'2 file(s) queued' in B6.log(), 30))
    time.sleep(6)                                        # B6 has a host for A6: with normal mail it would have called by now
    check('... the answer is hold mail: it waits in the outbound (.hlo), not sent by a call of its own',
          not os.path.exists(ga6) and not os.path.exists(gb6) and os.path.exists(os.path.join(B6.out, '006e0128.hlo'))
          and open(os.path.join(B6.out, '006e0128.hlo')).read().split() == [os.path.join(files, 'this.arc'), os.path.join(files, 'nodelist.001')]
          and b'starting batch 2' not in B6.log())
    open(os.path.join(A6.dir, 'ping.txt'), 'w').write('ping')
    subprocess.run([exe, 'queue', '-O', A6.out, '-Z', '1', '-t', '1:110/106', '-x', os.path.join(A6.dir, 'ping.txt')], check=True, capture_output=True)
    check('... the asker calls again and picks it up',
          wait(lambda: os.path.exists(ga6) and os.path.exists(gb6), 30) and open(ga6, 'rb').read() == b'ARC data')
    A6.stop()
    B6.stop()

    # the command fails: nothing is sent; a wrong password: a note and no file
    os.environ['STUB_FAIL'] = '1'
    B3 = Node('b3', '1:110/102', 24633, 'link 1:110/292\n  host 127.0.0.1\n  port 24634\n  password s\n', 'freq yes\non-freq %s\n' % stub)
    A3 = Node('a3', '1:110/292', 24634, 'link 1:110/102\n  host 127.0.0.1\n  port 24633\n  password s\n')
    B3.start()
    rq(A3.out, '1:110/102', 'this.arc', '!that')
    A3.start()
    check('a command that fails: logged, nothing sent, the request removed',
          wait(lambda: b'the command failed, nothing sent' in B3.log(), 20) and not os.path.exists(os.path.join(A3.inb, 'this.arc'))
          and not [f for f in os.listdir(B3.inb) if f.endswith('.req')])
    A3.stop()
    B3.stop()
    del os.environ['STUB_FAIL']

    # freq no (the default): the .req is an ordinary file; a caller without a password: not answered unless freq-unsecure yes
    open(called, 'w').close()
    B4 = Node('b4', '1:110/103', 24635, 'link 1:110/293\n  password s\n  answer-only yes\n', 'on-freq %s\n' % stub)
    A4 = Node('a4', '1:110/293', 24636, 'link 1:110/103\n  host 127.0.0.1\n  port 24635\n  password s\n')
    B4.start()
    rq(A4.out, '1:110/103', 'this.arc', '!that')
    A4.start()
    check('freq no (default): the .req stays in the inbound like any file, the command is not run',
          wait(lambda: os.path.exists(os.path.join(B4.inb, '006e0125.req')), 20) and open(called).read() == '')
    A4.stop()
    B4.stop()

    unsec = os.path.join(work, 'unsecure')
    B5 = Node('b5', '1:110/104', 24637, '', 'freq yes\non-freq %s\naccept-unknown yes\ninbound-unsecure %s\n' % (stub, unsec))
    A5 = Node('a5', '1:110/294', 24638, 'link 1:110/104\n  host 127.0.0.1\n  port 24637\n')
    B5.start()
    rq(A5.out, '1:110/104', 'this.arc', '!that')
    A5.start()
    check('a caller without a password: the request is ignored (freq-unsecure no), logged, the command not run',
          wait(lambda: b'ignored: the session had no password' in B5.log(), 20) and open(called).read() == '')
    A5.stop()
    B5.stop()
    # ---------------------------------------------------------------- SRIF (on-freq-srif) and the delete rule
    for n in ('keep.txt', 'erase.txt', 'minus.txt', 'plain.txt', 'nat.txt', 'natdel.txt'):
        open(os.path.join(files, n), 'wb').write(n.encode())
    copy = os.path.join(work, 'srif.copy')
    srif_stub = os.path.join(work, 'srifstub.py')
    open(srif_stub, 'w').write(SRIF_STUB.replace('FILES', files).replace('COPYPATH', repr(copy)))
    os.chmod(srif_stub, 0o755)
    B7 = Node('b7', '1:110/107', 24651, 'link 1:110/297\n  host 127.0.0.1\n  port 24652\n  password secret\n',
              'freq yes\non-freq-srif %s\n' % srif_stub)
    A7 = Node('a7', '1:110/297', 24652, 'link 1:110/107\n  host 127.0.0.1\n  port 24651\n  password secret\n')
    B7.start()
    rq(A7.out, '1:110/107', 'keep.txt', 'erase.txt', 'minus.txt', 'plain.txt', 'made.lst', 'lnk.txt', 'gone.zip')
    A7.start()
    got7 = lambda n: os.path.join(A7.inb, n)
    check('SRIF: all the files named in the response list arrive (+, =, -, no prefix, a list the command made in MKBINK_TMP, a link)',
          wait(lambda: all(os.path.exists(got7(n)) for n in ('keep.txt', 'erase.txt', 'minus.txt', 'plain.txt', 'made.lst', 'lnk.txt')), 40),
          sorted(os.listdir(A7.inb)))
    check('... and their contents are right', open(got7('keep.txt')).read() == 'keep.txt' and open(got7('made.lst')).read() == 'made by the command')
    wait(lambda: b'queued' in B7.log() and b'session complete' in B7.log(), 10)
    time.sleep(2)
    lg7 = B7.log().decode('latin-1')
    check('delete rule: "=" and "-" for files that are not in freq-tmp are ignored (logged), the files are still there',
          os.path.exists(os.path.join(files, 'erase.txt')) and os.path.exists(os.path.join(files, 'minus.txt')) and
          'erase.txt is not a plain file directly in' in lg7 and 'the delete mark is ignored' in lg7)
    tmp7 = os.path.join(B7.inb, 'freq-tmp')
    check('delete rule: the list the command made in freq-tmp (MKBINK_TMP) is deleted after it was sent', not os.path.exists(os.path.join(tmp7, 'made.lst')) or
          wait(lambda: not os.path.exists(os.path.join(tmp7, 'made.lst')), 10))
    check('delete rule: a symbolic link in freq-tmp with "=": the delete mark is ignored, the link and what it points to are kept',
          os.path.exists(os.path.join(files, 'keep.txt')) and os.path.islink(os.path.join(tmp7, 'lnk.txt')) and 'lnk.txt is not a plain file directly in' in lg7, (os.path.islink(os.path.join(tmp7, 'lnk.txt')), [l for l in lg7.split(chr(10)) if 'lnk' in l or 'delete' in l][:6]))
    check('... the freq-tmp directory is private (mode 700)',
          oct(os.stat(tmp7).st_mode & 0o777) == '0o700')
    sc = open(copy).read() if os.path.exists(copy) else ''
    check('the SRIF file: Sysop, AKA, Baud, Time, RequestList, ResponseList, RemoteStatus PROTECTED, SystemStatus LISTED, OurAKA, Mailer',
          all(k in sc for k in ('Sysop ', 'AKA 1:110/297', 'Baud ', 'Time -1', 'RequestList ', 'ResponseList ', 'RemoteStatus PROTECTED', 'SystemStatus LISTED',
                                'OurAKA 1:110/107', 'Mailer mkbink', 'SessionProtocoll BINKP', 'TRANX ')), sc)
    check('... the session password is not in it', 'secret' not in sc and 'Password' not in sc)
    check('... the SRIF file, the request and the response list are removed afterwards',
          not [f for f in os.listdir(B7.inb) if f.endswith(('.srif', '.rsp', '.req'))])
    A7.stop()
    B7.stop()

    # the native interface: a "^" outside freq-tmp is ignored too, inside it the file goes
    natstub = os.path.join(work, 'natstub.py')
    open(natstub, 'w').write(NAT_STUB.replace('FILES', files))
    os.chmod(natstub, 0o755)
    B8 = Node('b8', '1:110/108', 24653, 'link 1:110/298\n  host 127.0.0.1\n  port 24654\n  password secret\n', 'freq yes\non-freq %s\n' % natstub)
    A8 = Node('a8', '1:110/298', 24654, 'link 1:110/108\n  host 127.0.0.1\n  port 24653\n  password secret\n')
    B8.start()
    rq(A8.out, '1:110/108', 'natdel.txt', 'made2.lst')
    A8.start()
    check('native interface: both files arrive', wait(lambda: os.path.exists(os.path.join(A8.inb, 'natdel.txt')) and os.path.exists(os.path.join(A8.inb, 'made2.lst')), 40))
    time.sleep(2)
    check('... "^" on a file outside freq-tmp: ignored, the file is kept', os.path.exists(os.path.join(files, 'natdel.txt')) and b'natdel.txt is not a plain file directly in' in B8.log())
    check('... "^" on a file in freq-tmp: deleted after it was sent', wait(lambda: not os.path.exists(os.path.join(B8.inb, 'freq-tmp', 'made2.lst')), 10))
    A8.stop()
    B8.stop()
finally:
    for p in procs:
        if p.poll() is None:
            p.kill()
    shutil.rmtree(work, ignore_errors=True)
print('failures: %d' % fails)
sys.exit(1 if fails else 0)
