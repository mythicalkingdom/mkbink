#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Attach (FrontDoor) style outbound: netmail *.msg files plus attached files.

The *.msg files are written here, and the packets mkbink builds are parsed here, both from FTS-0001 / FSC-0048
alone (not with the MKMsg units mkbink uses).  A Python peer answers; mkbink polls it.
usage: tests/attachtest.py"""
import os, shutil, socket, struct, subprocess, sys, tempfile, time

here = os.path.dirname(os.path.abspath(__file__))
exe = os.path.realpath(os.path.join(here, '..', 'build', 'mkbink'))
work = tempfile.mkdtemp(prefix='mkat')
fails = 0

M_NUL, M_ADR, M_PWD, M_FILE, M_OK, M_EOB, M_GOT, M_ERR, M_BSY, M_GET, M_SKIP = range(11)


def check(name, ok, extra=''):
    global fails
    print(('ok   ' if ok else 'FAIL ') + name + ((' -- ' + str(extra)) if (extra and not ok) else ''))
    if not ok:
        fails += 1


# ---- *.msg writer (FTS-0001) ----------------------------------------------------------------------------
ATTR_PRIVATE, ATTR_CRASH, ATTR_SENT, ATTR_ATTACH, ATTR_KILL, ATTR_LOCAL, ATTR_HOLD = 1, 2, 8, 0x10, 0x80, 0x100, 0x200


def write_msg(netmail, num, to_addr, subj, text, attr, frm_addr=(1, 1, 1, 0), to_name='Sysop', from_name='Tester'):
    z, n, f, p = to_addr
    oz, on, of, op = frm_addr
    h = bytearray(190)
    h[0:len(from_name)] = from_name.encode()
    h[36:36 + len(to_name)] = to_name.encode()
    h[72:72 + len(subj)] = subj.encode()
    h[144:144 + 19] = b'16 Nov 26  12:00:00'
    struct.pack_into('<HHHHH', h, 166, f, of, 0, on, n)       # destNode, origNode, cost, origNet, destNet
    struct.pack_into('<HH', h, 184, 0, attr)                  # reply, attr
    kl = '\x01INTL %d:%d/%d %d:%d/%d\r' % (z, n, f, oz, on, of)
    os.makedirs(netmail, exist_ok=True)
    with open(os.path.join(netmail, '%d.msg' % num), 'wb') as fh:
        fh.write(bytes(h) + kl.encode() + text.encode('latin1') + b'\0')


def read_attr(netmail, num):
    p = os.path.join(netmail, '%d.msg' % num)
    if not os.path.exists(p):
        return None
    with open(p, 'rb') as fh:
        fh.seek(186)
        return struct.unpack('<H', fh.read(2))[0]


def read_msg(path):
    d = open(path, 'rb').read()
    subj = d[72:144].split(b'\0')[0].decode('latin1')
    attr = struct.unpack_from('<H', d, 186)[0]
    destnode, orignode, cost, orignet, destnet = struct.unpack_from('<HHHHH', d, 166)
    text = d[190:].split(b'\0')[0].decode('latin1')
    return dict(subj=subj, attr=attr, dest=(destnet, destnode), orig=(orignet, orignode), text=text,
                to=d[36:72].split(b'\0')[0].decode(), frm=d[0:36].split(b'\0')[0].decode())


# ---- packet parser (FTS-0001 type 2, FSC-0048 type 2+ header) -----------------------------------------
def parse_pkt(data):
    hdr = struct.unpack_from('<14H', data, 0)
    info = dict(orignode=hdr[0], destnode=hdr[1], pkttype=hdr[9], orignet=hdr[10], destnet=hdr[11])
    cap = struct.unpack_from('<H', data, 44)[0]
    capval = struct.unpack_from('>H', data, 40)[0]
    info['type2plus'] = (cap == capval) and (cap & 1) == 1
    info['origzone'], info['destzone'] = struct.unpack_from('<HH', data, 46)
    info['origpoint'], info['destpoint'] = struct.unpack_from('<HH', data, 50)
    pos, msgs = 58, []
    while True:
        t = struct.unpack_from('<H', data, pos)[0]
        if t == 0:
            pos += 2
            break
        assert t == 2, 'bad message type %d at %d' % (t, pos)
        on, dn, onet, dnet, attr, cost = struct.unpack_from('<6H', data, pos + 2)
        date = data[pos + 14:pos + 34]
        pos += 34
        parts = []
        for _ in range(4):
            e = data.index(b'\0', pos)
            parts.append(data[pos:e].decode('latin1'))
            pos = e + 1
        msgs.append(dict(orig=(onet, on), dest=(dnet, dn), attr=attr, to=parts[0], frm=parts[1], subj=parts[2],
                         text=parts[3], date=date))
    info['msgs'] = msgs
    info['trailing'] = len(data) - pos
    return info


# ---- the peer ---------------------------------------------------------------------------------------------------
class Link:
    def __init__(self, s):
        self.s, self.buf = s, b''

    def send_cmd(self, cid, arg=''):
        d = bytes([cid]) + arg.encode('latin1')
        self.s.sendall(struct.pack('>H', 0x8000 | len(d)) + d)

    def send_data(self, b):
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


def serve(port, addr='2:2/2.0@fidonet', pwd='pw'):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    return srv


def peer_session(srv, store, pwd='pw'):
    """answer one call; collect received files into store {name: bytes}; returns the order the files arrived in"""
    srv.settimeout(20)
    c, _ = srv.accept()
    L = Link(c)
    L.send_cmd(M_ADR, '2:2/2.0@fidonet')
    got = {}
    while M_ADR not in got or M_PWD not in got:
        k, cid, a = L.recv()
        if k == 'cmd' and cid in (M_ADR, M_PWD):
            got[cid] = a
    L.send_cmd(M_OK, 'secure')
    order, cur, eob = [], None, False
    sent_eob = False
    while True:
        try:
            k, cid, a = L.recv()
        except EOFError:
            break
        if k == 'data':
            cur['buf'] += a
            if len(cur['buf']) == cur['size']:
                store[cur['name']] = bytes(cur['buf'])
                L.send_cmd(M_GOT, '%s %d %d' % (cur['name'], cur['size'], cur['time']))
                cur = None
        elif cid == M_FILE:
            p = a.split()
            cur = dict(name=p[0], size=int(p[1]), time=int(p[2]), buf=bytearray())
            order.append(p[0])
            if cur['size'] == 0:
                store[cur['name']] = b''
                L.send_cmd(M_GOT, '%s 0 %d' % (cur['name'], cur['time']))
                cur = None
        elif cid == M_EOB:
            eob = True
            if not sent_eob:
                L.send_cmd(M_EOB)
                sent_eob = True
            break
        elif cid in (M_ERR, M_BSY):
            order.append('ERR ' + a)
            break
    try:
        c.settimeout(3)
        while c.recv(65536):
            pass
    except Exception:
        pass
    c.close()
    return order


def poll(port, *extra):
    return subprocess.run([exe, 'poll', '127.0.0.1:%d' % port, '-a', '1:1/1', '-r', '2:2/2', '-P', 'pw',
                           '-i', os.path.join(work, 'in'), '-Z', '1'] + list(extra),
                          capture_output=True, text=True, timeout=60)


def run_peer_and_poll(srv, port, *extra):
    import threading
    store = {}
    res = {}
    t = threading.Thread(target=lambda: res.update(order=peer_session(srv, store)))
    t.start()
    r = poll(port, *extra)
    t.join(30)
    return r, store, res.get('order', [])


# ---------------------------------------------------------------------------------------------------------------------
def main():
    if subprocess.run([exe, 'poll', 'x', '-M', 'a', '-A', 'b', '-a', '1:1/1'], capture_output=True, text=True).stderr.startswith(
            'This build has no attach'):
        print('this mkbink was built without the MKMsg units: nothing to test')
        return 0

    net = os.path.join(work, 'netmail')
    att = os.path.join(work, 'attach')
    os.makedirs(os.path.join(att, '2.2.2.0'))
    a_bin = os.urandom(70000)
    b_bin = os.urandom(5000)
    open(os.path.join(att, '2.2.2.0', 'a.bin'), 'wb').write(a_bin)
    b_path = os.path.join(work, 'b.bin')
    open(b_path, 'wb').write(b_bin)

    # 1 normal netmail, 2 crash netmail, 3 attach (bare name, delete after), 4 crash attach (full path, keep, kill msg),
    # 5 for somebody else, 6 already sent, 7 hold, 8 attach of a file that does not exist
    write_msg(net, 1, (2, 2, 2, 0), 'Hello', 'normal mail\r--- end\r', ATTR_PRIVATE | ATTR_LOCAL)
    write_msg(net, 2, (2, 2, 2, 0), 'Urgent', 'crash mail\r', ATTR_PRIVATE | ATTR_CRASH | ATTR_LOCAL)
    write_msg(net, 3, (2, 2, 2, 0), '^a.bin', 'file a\r', ATTR_PRIVATE | ATTR_ATTACH | ATTR_LOCAL)
    write_msg(net, 4, (2, 2, 2, 0), b_path, 'file b\r', ATTR_PRIVATE | ATTR_ATTACH | ATTR_CRASH | ATTR_KILL | ATTR_LOCAL)
    write_msg(net, 5, (2, 2, 3, 0), 'Other', 'not for 2:2/2\r', ATTR_PRIVATE | ATTR_LOCAL)
    write_msg(net, 6, (2, 2, 2, 0), 'Old', 'already sent\r', ATTR_PRIVATE | ATTR_SENT)
    write_msg(net, 7, (2, 2, 2, 0), 'Held', 'hold\r', ATTR_PRIVATE | ATTR_HOLD)
    write_msg(net, 8, (2, 2, 2, 0), 'nothere.bin', 'no file\r', ATTR_PRIVATE | ATTR_ATTACH)

    port = 24611
    srv = serve(port)
    r, store, order = run_peer_and_poll(srv, port, '-M', net, '-A', att)
    check('poll exits 0', r.returncode == 0, r.stdout[-800:] + r.stderr)
    print('   arrival order:', order)
    check('crash first: file b, crash packet, then file a, then the normal packet',
          len(order) == 4 and order[0] == 'b.bin' and order[1].endswith('.pkt') and order[2] == 'a.bin'
          and order[3].endswith('.pkt'), order)
    check('files arrived intact', store.get('b.bin') == b_bin and store.get('a.bin') == a_bin)

    pk = [n for n in order if n.endswith('.pkt')]
    if len(pk) == 2:
        crash, norm = parse_pkt(store[pk[0]]), parse_pkt(store[pk[1]])
        check('packet is a type 2+ packet 1:1/1 -> 2:2/2', crash['pkttype'] == 2 and crash['type2plus'] and
              (crash['origzone'], crash['orignet'], crash['orignode']) == (1, 1, 1) and
              (crash['destzone'], crash['destnet'], crash['destnode']) == (2, 2, 2), crash)
        check('crash packet holds only message 2', [m['subj'] for m in crash['msgs']] == ['Urgent'] and crash['trailing'] == 0)
        m = norm['msgs'][0] if norm['msgs'] else {}
        check('normal packet holds only message 1 (not sent, other node, hold, attach ones)',
              [x['subj'] for x in norm['msgs']] == ['Hello'], [x['subj'] for x in norm['msgs']])
        check('message fields survive', m.get('to') == 'Sysop' and m.get('frm') == 'Tester' and
              m.get('dest') == (2, 2) and m.get('orig') == (1, 1) and
              m.get('text', '').startswith('\x01INTL 2:2/2 1:1/1\r') and 'normal mail' in m.get('text', ''), m)
        check('only private/crash attribute bits go out', m.get('attr') == ATTR_PRIVATE and
              crash['msgs'][0]['attr'] == ATTR_PRIVATE | ATTR_CRASH, (m.get('attr'), crash['msgs'][0]['attr']))
        check('a MSGID was added', '\x01MSGID: 1:1/1 ' in m.get('text', ''), m.get('text'))
        check('date kept', m.get('date', b'')[:19] == b'16 Nov 26  12:00:00')
    else:
        check('two packets arrived', False, order)

    check('msg 1 marked Sent', (read_attr(net, 1) or 0) & ATTR_SENT)
    check('msg 2 marked Sent', (read_attr(net, 2) or 0) & ATTR_SENT)
    check('msg 3 (attach) marked Sent', (read_attr(net, 3) or 0) & ATTR_SENT)
    check('msg 4 had Kill/Sent: deleted', read_attr(net, 4) is None)
    check('msg 5 (other node) untouched', read_attr(net, 5) == ATTR_PRIVATE | ATTR_LOCAL)
    check('msg 7 (hold) untouched when we call', read_attr(net, 7) == ATTR_PRIVATE | ATTR_HOLD)
    check('msg 8 (missing file) untouched', read_attr(net, 8) == ATTR_PRIVATE | ATTR_ATTACH)
    check('^file deleted after sending', not os.path.exists(os.path.join(att, '2.2.2.0', 'a.bin')))
    check('plain file kept', os.path.exists(b_path))
    check('no lock or temporary packet left',
          not [f for f in os.listdir(att) if f.endswith('.bsy')] and
          not [f for f in os.listdir(os.path.join(att, 'packets', '2.2.2.0')) if f.endswith('.pkt')]
          if os.path.isdir(os.path.join(att, 'packets', '2.2.2.0')) else True)

    # a second call has nothing left
    r, store, order = run_peer_and_poll(srv, port, '-M', net, '-A', att)
    check('second call sends nothing', r.returncode == 0 and order == [], (order, r.stdout[-400:]))

    # queue: attach style
    q = os.path.join(work, 'queued.txt')
    open(q, 'w').write('queued file\n')
    r = subprocess.run([exe, 'queue', '-M', net, '-A', att, '-a', '1:1/1', '-t', '2:2/2', '-F', 'C', q],
                       capture_output=True, text=True)
    check('queue works', r.returncode == 0, r.stdout + r.stderr)
    mp = [l.split('-> ')[-1].strip() for l in r.stdout.splitlines() if '->' in l]
    if mp and os.path.exists(mp[0]):
        m = read_msg(mp[0])
        check('queued message: file attach, crash, private, local, to 2:2/2 from 1:1/1',
              m['attr'] & ATTR_ATTACH and m['attr'] & ATTR_CRASH and m['attr'] & ATTR_PRIVATE and m['attr'] & ATTR_LOCAL
              and m['dest'] == (2, 2) and m['orig'] == (1, 1), m)
        check('subject names a copy in <attach>/<link>/', m['subj'] == os.path.join(att, '2.2.2.0', 'queued.txt'), m['subj'])
    else:
        check('queue printed the message path', False, r.stdout)
    hq = os.path.join(work, 'held.txt')
    open(hq, 'w').write('held file\n')
    r = subprocess.run([exe, 'queue', '-M', net, '-A', att, '-a', '1:1/1', '-t', '2:2/2', '-F', 'H', hq],
                       capture_output=True, text=True)
    hp = [l.split('-> ')[-1].strip() for l in r.stdout.splitlines() if '->' in l]
    hm = read_msg(hp[0]) if hp and os.path.exists(hp[0]) else {}
    check('queue -F H sets Hold (0x0200) and not Crash', r.returncode == 0 and hm.get('attr', 0) & ATTR_HOLD and
          not hm.get('attr', 0) & ATTR_CRASH, (r.stdout + r.stderr, hm))
    r = subprocess.run([exe, 'queue', '-M', net, '-A', att, '-a', '1:1/1', '-t', '2:2/2', '-F', 'X', q],
                       capture_output=True, text=True)
    check('an unknown flavour is refused', r.returncode != 0 and 'lavour' in (r.stdout + r.stderr))
    r, store, order = run_peer_and_poll(srv, port, '-M', net, '-A', att)
    check('queued file is sent, the held one is not (we called)', order == ['queued.txt'] and store.get('queued.txt') == b'queued file\n', (order, r.stdout[-500:]))

    # hold mail goes out only when the remote calls us: mkbink answers, a second mkbink polls it
    net3, att3 = os.path.join(work, 'netmail3'), os.path.join(work, 'attach3')
    write_msg(net3, 1, (1, 1, 1, 0), 'Held mail', 'wait for pickup\r', ATTR_PRIVATE | ATTR_HOLD | ATTR_LOCAL, frm_addr=(2, 2, 2, 0))
    write_msg(net3, 2, (1, 1, 1, 0), 'Plain mail', 'normal\r', ATTR_PRIVATE | ATTR_LOCAL, frm_addr=(2, 2, 2, 0))
    lp = 24613
    inb = os.path.join(work, 'in3')
    ln = subprocess.Popen([exe, 'listen', '-a', '2:2/2', '-r', '1:1/1', '-P', 'pw', '-p', str(lp), '-b', '127.0.0.1',
                           '-i', os.path.join(work, 'in4'), '-M', net3, '-A', att3, '-Z', '2'],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(1)
    try:
        r = subprocess.run([exe, 'poll', '127.0.0.1:%d' % lp, '-a', '1:1/1', '-r', '2:2/2', '-P', 'pw', '-i', inb,
                            '-o', os.path.join(work, 'nothing')], capture_output=True, text=True, timeout=60)
    finally:
        ln.terminate()
        ln.wait(10)
    got = sorted(os.listdir(inb)) if os.path.isdir(inb) else []
    check('caller receives both packets (normal first, hold last)', r.returncode == 0 and len(got) == 2, (got, r.stdout[-600:]))
    subs = []
    for f in sorted(got, key=lambda n: os.path.getmtime(os.path.join(inb, n))):
        subs.append([m['subj'] for m in parse_pkt(open(os.path.join(inb, f), 'rb').read())['msgs']])
    check('held message went out in its own packet after the normal one', subs == [['Plain mail'], ['Held mail']], subs)
    check('both marked Sent', (read_attr(net3, 1) or 0) & ATTR_SENT and (read_attr(net3, 2) or 0) & ATTR_SENT)

    # run mode: settings file with netmail/attach instead of bso
    net2, att2 = os.path.join(work, 'netmail2'), os.path.join(work, 'attach2')
    write_msg(net2, 1, (2, 2, 2, 0), 'Via run', 'sent by the mailer\r', ATTR_PRIVATE | ATTR_LOCAL)
    rp = 24612
    srv2 = serve(rp)
    conf = os.path.join(work, 'run.conf')
    open(conf, 'w').write('version 1\naddress 1:1/1\ninbound %s\nnetmail %s\nattach %s\nzone 1\nlisten no\n'
                          'retry-min 1\nretry-max 4\nscan-interval 1\n\nlink 2:2/2\n  host 127.0.0.1\n  port %d\n  password pw\n'
                          % (os.path.join(work, 'in2'), net2, att2, rp))
    r = subprocess.run([exe, 'check', '-f', conf], capture_output=True, text=True)
    check('check accepts netmail/attach', r.returncode == 0 and 'netmail' in r.stdout, r.stdout + r.stderr)
    bad = os.path.join(work, 'bad.conf')
    open(bad, 'w').write('version 1\naddress 1:1/1\nnetmail %s\n' % net2)
    r = subprocess.run([exe, 'check', '-f', bad], capture_output=True, text=True)
    check('check refuses netmail without attach', r.returncode != 0 and 'go together' in (r.stdout + r.stderr))
    proc = subprocess.Popen([exe, 'run', '-f', conf], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    store2 = {}
    try:
        order2 = peer_session(srv2, store2)
        time.sleep(1)
    finally:
        proc.terminate()
        proc.wait(10)
    check('run mode calls the link and sends the packet', len(order2) == 1 and order2[0].endswith('.pkt'), order2)
    if order2 and order2[0] in store2:
        check('... holding the message', [m['subj'] for m in parse_pkt(store2[order2[0]])['msgs']] == ['Via run'])
    check('... and marks it sent', (read_attr(net2, 1) or 0) & ATTR_SENT)

    # option checks
    r = subprocess.run([exe, 'poll', 'x', '-a', '1:1/1', '-M', net], capture_output=True, text=True)
    check('-M without -A is refused', r.returncode != 0 and '-A' in (r.stdout + r.stderr))
    r = subprocess.run([exe, 'poll', 'x', '-a', '1:1/1', '-M', net, '-A', att, '-O', work], capture_output=True, text=True)
    check('-M with -O is refused', r.returncode != 0 and 'not both' in (r.stdout + r.stderr))

    shutil.rmtree(work, ignore_errors=True)
    print('failures: %d' % fails)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
