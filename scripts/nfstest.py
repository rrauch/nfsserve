#!/usr/bin/env python3
"""
    sudo -u testuser ./nfstest.py /mnt/nfs
    ./nfstest.py /mnt/nfs --big-mb 0 -v          # skip the 100MB case
    ./nfstest.py /mnt/nfs --only rename
"""

import argparse
import errno
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time

MIB = 1024 * 1024

# ---------------------------------------------------------------- framework


class Fail(Exception):
    pass


class Skip(Exception):
    pass


TESTS = []


def test(name):
    def deco(fn):
        TESTS.append((name, fn))
        return fn
    return deco


def fail(msg):
    raise Fail(msg)


def skip(msg):
    raise Skip(msg)


def check(cond, msg):
    if not cond:
        raise Fail(msg)


def check_eq(got, want, what):
    if got != want:
        raise Fail("%s: got %r, want %r" % (what, got, want))


def ename(e):
    return errno.errorcode.get(e, str(e))


def expect_errno(wanted, fn, *a, **kw):
    """wanted: single errno or tuple. Returns the OSError."""
    if not isinstance(wanted, tuple):
        wanted = (wanted,)
    try:
        fn(*a, **kw)
    except OSError as e:
        if e.errno in wanted:
            return e
        raise Fail("expected %s, got %s (%s)"
                   % ("/".join(ename(x) for x in wanted), ename(e.errno), e))
    raise Fail("expected %s, call succeeded"
               % "/".join(ename(x) for x in wanted))


class Ctx(object):
    def __init__(self, dirpath, verbose):
        self.dir = dirpath
        self.verbose = verbose
        self.notes = []

    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def log(self, msg):
        self.notes.append(msg)
        if self.verbose:
            sys.stdout.write("         . %s\n" % msg)
            sys.stdout.flush()


# ---------------------------------------------------------------- data pattern

def _make_base(n):
    out = bytearray()
    h = hashlib.sha512(b"nfstest-pattern-v1").digest()
    while len(out) < n:
        out += h
        h = hashlib.sha512(h).digest()
    return bytes(out[:n])


BASE = _make_base(MIB)


def chunk(idx, size):
    """Deterministic block content, self-identifying so misordered/duplicated
    blocks are detected as well as corrupted ones."""
    hdr = b"BLK%012d\n" % idx
    if size <= len(hdr):
        return hdr[:size]
    body = BASE
    while len(body) < size:
        body = body + BASE
    return hdr + body[:size - len(hdr)]


def write_all(fd, data):
    off = 0
    while off < len(data):
        n = os.write(fd, data[off:])
        if n <= 0:
            fail("os.write returned %d" % n)
        off += n


def read_exact(fd, size):
    buf = b""
    while len(buf) < size:
        d = os.read(fd, size - len(buf))
        if not d:
            break
        buf += d
    return buf


def write_pattern(path, size, bs):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        off = i = 0
        while off < size:
            n = min(bs, size - off)
            write_all(fd, chunk(i, n))
            off += n
            i += 1
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_pattern(path, size, bs):
    st = os.stat(path)
    check_eq(st.st_size, size, "size of %s" % os.path.basename(path))
    fd = os.open(path, os.O_RDONLY)
    try:
        off = i = 0
        while off < size:
            n = min(bs, size - off)
            got = read_exact(fd, n)
            check_eq(len(got), n, "short read at offset %d" % off)
            if got != chunk(i, n):
                fail("data mismatch at offset %d (block %d, %d bytes)"
                     % (off, i, n))
            off += n
            i += 1
        check_eq(os.read(fd, 1), b"", "extra data past EOF")
    finally:
        os.close(fd)


def sha256_of(path, bs=MIB):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            d = f.read(bs)
            if not d:
                break
            h.update(d)
    return h.hexdigest()


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


def spit(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        write_all(fd, data)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- 1. read/write

@test("rw/write-read-verify")
def t_rw_basic(t):
    for bs in (4096, MIB):
        p = t.p("rw-bs%d" % bs)
        write_pattern(p, 3 * bs + 137, bs)
        verify_pattern(p, 3 * bs + 137, bs)
        t.log("bs=%d ok" % bs)


@test("rw/append")
def t_rw_append(t):
    p = t.p("append")
    spit(p, b"A" * 1000)
    fd = os.open(p, os.O_WRONLY | os.O_APPEND)
    try:
        write_all(fd, b"B" * 500)
    finally:
        os.close(fd)
    data = slurp(p)
    check_eq(len(data), 1500, "size after append")
    check_eq(data, b"A" * 1000 + b"B" * 500, "content after append")
    check_eq(os.stat(p).st_size, 1500, "stat size after append")


@test("rw/overwrite-at-offset")
def t_rw_overwrite(t):
    p = t.p("overwrite")
    orig = chunk(7, 64 * 1024)
    spit(p, orig)
    patch = b"\xa5" * 4096
    fd = os.open(p, os.O_WRONLY)
    try:
        os.lseek(fd, 8192, os.SEEK_SET)
        write_all(fd, patch)
    finally:
        os.close(fd)
    want = orig[:8192] + patch + orig[8192 + 4096:]
    got = slurp(p)
    check_eq(len(got), len(orig), "size unchanged after in-place overwrite")
    if got != want:
        for i in range(len(want)):
            if got[i:i + 1] != want[i:i + 1]:
                fail("first difference at offset %d" % i)
    check_eq(os.stat(p).st_size, len(orig), "stat size after overwrite")


@test("rw/reopen-o-trunc")
def t_rw_trunc_open(t):
    p = t.p("otrunc")
    spit(p, b"X" * 8192)
    fd = os.open(p, os.O_WRONLY | os.O_TRUNC)
    os.close(fd)
    check_eq(os.stat(p).st_size, 0, "size after O_TRUNC")
    check_eq(slurp(p), b"", "content after O_TRUNC")


@test("rw/1MB-sha256")
def t_rw_1mb(t):
    p = t.p("file-1mb")
    h = hashlib.sha256()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        for i in range(16):
            d = chunk(i, 64 * 1024)
            write_all(fd, d)
            h.update(d)
        os.fsync(fd)
    finally:
        os.close(fd)
    check_eq(os.stat(p).st_size, MIB, "size")
    check_eq(sha256_of(p), h.hexdigest(), "sha256 of 1MB file")


@test("rw/bigfile-sha256")
def t_rw_big(t):
    mb = t.big_mb
    if mb <= 0:
        skip("--big-mb 0")
    p = t.p("file-big")
    h = hashlib.sha256()
    t0 = time.time()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        for i in range(mb):
            d = chunk(i, MIB)
            write_all(fd, d)
            h.update(d)
        os.fsync(fd)
    finally:
        os.close(fd)
    wsec = time.time() - t0
    check_eq(os.stat(p).st_size, mb * MIB, "size of %dMB file" % mb)
    t0 = time.time()
    got = sha256_of(p)
    rsec = time.time() - t0
    check_eq(got, h.hexdigest(), "sha256 of %dMB file" % mb)
    t.log("write %.1f MB/s, read %.1f MB/s"
          % (mb / max(wsec, 1e-6), mb / max(rsec, 1e-6)))


# ---------------------------------------------------------------- 2. directory

@test("dir/mkdir-rmdir")
def t_dir_mkdir(t):
    d = t.p("d1")
    os.mkdir(d)
    check(os.path.isdir(d), "mkdir did not create a directory")
    os.rmdir(d)
    check(not os.path.exists(d), "rmdir left the directory behind")
    deep = t.p("a", "b", "c")
    os.makedirs(deep)
    check(os.path.isdir(deep), "makedirs failed")


def _readdir_case(t, n):
    d = t.p("dir%d" % n)
    os.mkdir(d)
    want = set()
    for i in range(n):
        name = "f%05d" % i
        spit(os.path.join(d, name), b"x")
        want.add(name)
    names = [e.name for e in os.scandir(d)]
    check_eq(len(names), len(set(names)),
             "duplicate names in readdir of %d entries (%d/%d unique)"
             % (n, len(set(names)), len(names)))
    check_eq(set(names), want, "readdir contents of %d-entry dir" % n)
    again = sorted(os.listdir(d))
    check_eq(again, sorted(names), "re-read of dir gave a different set")
    return d


@test("dir/readdir-10")
def t_dir_10(t):
    _readdir_case(t, 10)


@test("dir/readdir-100")
def t_dir_1000(t):
    _readdir_case(t, 100)


@test("dir/recursive-walk")
def t_dir_walk(t):
    root = t.p("tree")
    expect_files = set()
    expect_dirs = set()
    for a in range(3):
        for b in range(3):
            d = os.path.join(root, "l%d" % a, "m%d" % b)
            os.makedirs(d)
            expect_dirs.add(d)
            expect_dirs.add(os.path.dirname(d))
            for c in range(2):
                p = os.path.join(d, "f%d" % c)
                spit(p, b"leaf")
                expect_files.add(p)
    got_files, got_dirs = set(), set()
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath != root:
            got_dirs.add(dirpath)
        for f in filenames:
            got_files.add(os.path.join(dirpath, f))
    check_eq(got_files, expect_files, "files found by walk")
    check_eq(got_dirs, expect_dirs, "dirs found by walk")


# ---------------------------------------------------------------- 3. namespace

@test("ns/rename-same-dir")
def t_ns_rename(t):
    a, b = t.p("r-a"), t.p("r-b")
    spit(a, b"payload")
    os.rename(a, b)
    check(not os.path.exists(a), "source still exists after rename")
    check_eq(slurp(b), b"payload", "content after rename")


@test("ns/rename-across-dirs")
def t_ns_rename_cross(t):
    d1, d2 = t.p("x1"), t.p("x2")
    os.mkdir(d1)
    os.mkdir(d2)
    a = os.path.join(d1, "f")
    b = os.path.join(d2, "f")
    spit(a, b"cross")
    os.rename(a, b)
    check(not os.path.exists(a), "source still exists after cross-dir rename")
    check_eq(slurp(b), b"cross", "content after cross-dir rename")
    check_eq(os.listdir(d1), [], "source dir not empty after rename")
    check_eq(os.listdir(d2), ["f"], "target dir listing after rename")


@test("ns/rename-over-existing")
def t_ns_rename_over(t):
    a, b = t.p("ov-a"), t.p("ov-b")
    spit(a, b"new-content")
    spit(b, b"old-content-longer")
    os.rename(a, b)
    check(not os.path.exists(a), "source still exists")
    check_eq(slurp(b), b"new-content", "target content after clobbering rename")
    check_eq(os.stat(b).st_size, len(b"new-content"), "target size")


@test("ns/rename-dir")
def t_ns_rename_dir(t):
    d1, d2 = t.p("rd-a"), t.p("rd-b")
    os.mkdir(d1)
    spit(os.path.join(d1, "inside"), b"i")
    os.rename(d1, d2)
    check(not os.path.exists(d1), "old dir name still present")
    check_eq(os.listdir(d2), ["inside"], "renamed dir contents")


@test("ns/unlink")
def t_ns_unlink(t):
    p = t.p("victim")
    spit(p, b"bye")
    d = os.path.dirname(p)
    check("victim" in os.listdir(d), "file missing from readdir before unlink")
    os.unlink(p)
    check(not os.path.exists(p), "file still stat-able after unlink")
    check("victim" not in os.listdir(d), "file still in readdir after unlink")


@test("ns/symlink-readlink")
def t_ns_symlink(t):
    tgt = t.p("sym-target")
    spit(tgt, b"target-data")
    link = t.p("sym-link")
    os.symlink("sym-target", link)
    check_eq(os.readlink(link), "sym-target", "readlink result")
    check(os.path.islink(link), "lstat does not report a symlink")
    check_eq(slurp(link), b"target-data", "content read through symlink")
    dangling = t.p("sym-dangling")
    os.symlink("no-such-file-here", dangling)
    check_eq(os.readlink(dangling), "no-such-file-here", "dangling readlink")
    expect_errno(errno.ENOENT, os.stat, dangling)
    absl = t.p("sym-abs")
    os.symlink(tgt, absl)
    check_eq(os.readlink(absl), tgt, "absolute readlink result")

# ---------------------------------------------------------------- 4. attributes

@test("attr/size-after-close")
def t_attr_size(t):
    for size in (0, 1, 511, 4096, 100000):
        p = t.p("sz-%d" % size)
        spit(p, b"z" * size)
        check_eq(os.stat(p).st_size, size, "stat size for %d-byte file" % size)


@test("attr/chmod")
def t_attr_chmod(t):
    p = t.p("modes")
    spit(p, b"m")
    for mode in (0o644, 0o600, 0o755, 0o700, 0o666):
        os.chmod(p, mode)
        got = os.stat(p).st_mode & 0o7777
        check_eq(oct(got), oct(mode), "mode after chmod")
    d = t.p("modes-dir")
    os.mkdir(d)
    os.chmod(d, 0o700)
    check_eq(oct(os.stat(d).st_mode & 0o7777), oct(0o700), "dir mode after chmod")


@test("attr/mtime-changes-on-write")
def t_attr_mtime(t):
    p = t.p("mtime")
    spit(p, b"first")
    m1 = os.stat(p).st_mtime
    time.sleep(1.2)                       # tolerate 1s timestamp granularity
    fd = os.open(p, os.O_WRONLY | os.O_APPEND)
    try:
        write_all(fd, b"second")
    finally:
        os.close(fd)
    m2 = os.stat(p).st_mtime
    check(m2 > m1, "mtime did not advance on write (%r -> %r)" % (m1, m2))
    t.log("mtime %r -> %r (delta %.3fs)" % (m1, m2, m2 - m1))


@test("attr/truncate-grow-shrink")
def t_attr_truncate(t):
    p = t.p("trunc")
    body = chunk(3, 8192)
    spit(p, body)

    os.truncate(p, 20000)
    check_eq(os.stat(p).st_size, 20000, "size after grow")
    got = slurp(p)
    check_eq(len(got), 20000, "bytes read after grow")
    check_eq(got[:8192], body, "original data after grow")
    check_eq(got[8192:], b"\x00" * (20000 - 8192), "tail not zero-filled")

    os.truncate(p, 4096)
    check_eq(os.stat(p).st_size, 4096, "size after shrink")
    check_eq(slurp(p), body[:4096], "content after shrink")

    os.truncate(p, 0)
    check_eq(os.stat(p).st_size, 0, "size after truncate to 0")
    check_eq(slurp(p), b"", "content after truncate to 0")


# ---------------------------------------------------------------- 5. errors

@test("err/enoent")
def t_err_enoent(t):
    expect_errno(errno.ENOENT, os.open, t.p("no-such-file"), os.O_RDONLY)
    expect_errno(errno.ENOENT, os.stat, t.p("no-such-file"))
    expect_errno(errno.ENOENT, os.unlink, t.p("no-such-file"))
    expect_errno(errno.ENOENT, os.listdir, t.p("no-such-dir"))


@test("err/eexist")
def t_err_eexist(t):
    p = t.p("excl")
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    os.close(fd)
    expect_errno(errno.EEXIST, os.open, p,
                 os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    d = t.p("excl-dir")
    os.mkdir(d)
    expect_errno(errno.EEXIST, os.mkdir, d)


@test("err/rmdir-nonempty-fails")
def t_err_rmdir_nonempty(t):
    """Removing a non-empty directory must fail (any errno) and must not
    remove the directory or its contents."""
    d = t.p("full-dir")
    os.mkdir(d)
    child = os.path.join(d, "child")
    spit(child, b"c")
    try:
        os.rmdir(d)
    except OSError as e:
        t.log("rmdir non-empty -> %s" % ename(e.errno))
    else:
        fail("rmdir of non-empty directory succeeded")
    check(os.path.isdir(d), "directory removed despite failed rmdir")
    check_eq(slurp(child), b"c", "child damaged by failed rmdir")


@test("err/eisdir-enotdir")
def t_err_isdir(t):
    d = t.p("isdir")
    os.mkdir(d)
    expect_errno(errno.EISDIR, os.open, d, os.O_WRONLY)
    f = t.p("plainfile")
    spit(f, b"f")
    expect_errno(errno.ENOTDIR, os.stat, os.path.join(f, "below"))
    expect_errno(errno.ENOTDIR, os.listdir, f)


# ------------------------------------------------- 6. cache coherence (2 procs)

def child(*args):
    """Run this script's helper mode in a separate process."""
    cmd = [sys.executable, SELF, "--child"] + [str(a) for a in args]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        fail("helper %s failed (rc=%d): %s"
             % (args, r.returncode, r.stderr.decode(errors="replace").strip()))
    return r.stdout.decode(errors="replace").strip()


def eventually(t, fn, what, timeout=5.0):
    """fn() -> (ok, detail). Passes immediately or after waiting; a wait is
    reported because same-client changes should be visible at once."""
    deadline = time.time() + timeout
    t0 = time.time()
    detail = None
    while True:
        ok, detail = fn()
        if ok:
            waited = time.time() - t0
            if waited > 0.05:
                t.log("%s only became visible after %.2fs" % (what, waited))
            return
        if time.time() >= deadline:
            fail("%s not visible after %.1fs: %s" % (what, timeout, detail))
        time.sleep(0.1)


@test("coh/write-then-read-other-process")
def t_coh_write(t):
    p = t.p("coh-write")
    spit(p, b"initial-content")
    check_eq(slurp(p), b"initial-content", "pre-read in this process")
    child("writeclose", p, "updated-by-child")
    eventually(t, lambda: (slurp(p) == b"updated-by-child", repr(slurp(p))),
               "content written by other process")
    check_eq(os.stat(p).st_size, len(b"updated-by-child"), "size after child write")


@test("coh/truncate-then-stat")
def t_coh_truncate(t):
    p = t.p("coh-trunc")
    spit(p, b"y" * 10000)
    check_eq(os.stat(p).st_size, 10000, "size before child truncate")
    child("truncate", p, 512)
    eventually(t, lambda: (os.stat(p).st_size == 512, os.stat(p).st_size),
               "size after truncate by other process")
    check_eq(len(slurp(p)), 512, "bytes readable after child truncate")


@test("coh/create-then-readdir")
def t_coh_create(t):
    d = t.p("coh-dir")
    os.mkdir(d)
    check_eq(os.listdir(d), [], "new dir not empty")
    p = os.path.join(d, "made-by-child")
    expect_errno(errno.ENOENT, os.stat, p)     # seeds a negative lookup
    child("create", p)
    eventually(t, lambda: ("made-by-child" in os.listdir(d), os.listdir(d)),
               "file created by other process (readdir)")
    eventually(t, lambda: (os.path.exists(p), "stat ENOENT"),
               "file created by other process (stat)")


@test("coh/unlink-then-stat")
def t_coh_unlink(t):
    p = t.p("coh-unlink")
    spit(p, b"doomed")
    check_eq(os.stat(p).st_size, 6, "size before child unlink")
    d = os.path.dirname(p)
    child("unlink", p)

    def gone():
        try:
            os.stat(p)
            return False, "still stat-able"
        except OSError as e:
            if e.errno == errno.ENOENT:
                return True, None
            return False, ename(e.errno)
    eventually(t, gone, "unlink by other process (stat)")
    eventually(t, lambda: (os.path.basename(p) not in os.listdir(d),
                           os.listdir(d)),
               "unlink by other process (readdir)")


# ---------------------------------------------------------------- child mode

def child_main(argv):
    op = argv[0]
    if op == "writeclose":
        spit(argv[1], argv[2].encode())
    elif op == "truncate":
        os.truncate(argv[1], int(argv[2]))
    elif op == "create":
        fd = os.open(argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(fd)
    elif op == "unlink":
        os.unlink(argv[1])
    elif op == "read":
        sys.stdout.write(slurp(argv[1]).decode(errors="replace"))
    else:
        sys.stderr.write("unknown child op %r\n" % op)
        return 2
    return 0


# ---------------------------------------------------------------- runner

def describe_mount(path):
    try:
        out = subprocess.run(["mount"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode(
                                 errors="replace")
    except Exception:
        return None
    real = os.path.realpath(path)
    best = None
    for line in out.splitlines():
        if " on " not in line:
            continue
        rest = line.split(" on ", 1)[1]
        mp = rest.split(" (", 1)[0].split(" type ", 1)[0].strip()
        if real == mp or real.startswith(mp.rstrip("/") + "/"):
            if best is None or len(mp) > len(best[0]):
                best = (mp, line.strip())
    return best[1] if best else None


def main():
    ap = argparse.ArgumentParser(
        description="Core NFSv4 client-visible correctness tests.")
    ap.add_argument("mountpoint", nargs="?", help="directory on the NFS mount")
    ap.add_argument("--big-mb", type=int, default=100,
                    help="size of the large-file test in MB, 0 to skip (100)")
    ap.add_argument("--only", action="append", default=[], metavar="SUBSTR",
                    help="run only tests whose name contains SUBSTR (repeatable)")
    ap.add_argument("--list", action="store_true", help="list test names and exit")
    ap.add_argument("--keep", action="store_true", help="do not delete test data")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--child", nargs=argparse.REMAINDER,
                    help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.child:
        return child_main(args.child)

    if args.list:
        for name, _ in TESTS:
            print(name)
        return 0

    if not args.mountpoint:
        ap.error("mountpoint is required")
    mp = args.mountpoint
    if not os.path.isdir(mp):
        sys.stderr.write("error: %s is not a directory\n" % mp)
        return 2

    selected = [(n, f) for n, f in TESTS
                if not args.only or any(s in n for s in args.only)]
    if not selected:
        sys.stderr.write("error: no tests matched --only\n")
        return 2

    root = os.path.join(mp, "nfstest.%s.%d" % (platform.node().split(".")[0],
                                               os.getpid()))
    print("=" * 72)
    print("nfstest.py   %s %s   python %s"
          % (platform.system(), platform.release(),
             platform.python_version()))
    print("mountpoint : %s" % os.path.realpath(mp))
    m = describe_mount(mp)
    if m:
        print("mount      : %s" % m)
    print("uid/gid    : %d/%d   umask %04o"
          % (os.getuid(), os.getgid(), _get_umask()))
    print("scratch    : %s" % root)
    print("=" * 72)

    try:
        os.mkdir(root)
    except OSError as e:
        sys.stderr.write("error: cannot create %s: %s\n" % (root, e))
        return 2

    npass = nfail = nskip = 0
    failures = []
    t_start = time.time()
    try:
        for i, (name, fn) in enumerate(selected, 1):
            tdir = os.path.join(root, "%02d-%s" % (i, name.replace("/", "_")))
            ctx = Ctx(tdir, args.verbose)
            ctx.big_mb = args.big_mb
            sys.stdout.write("[ .... ] %-34s" % name)
            sys.stdout.flush()
            t0 = time.time()
            status, detail = "PASS", None
            try:
                os.mkdir(tdir)
                fn(ctx)
            except Skip as e:
                status, detail = "SKIP", str(e)
            except Fail as e:
                status, detail = "FAIL", str(e)
            except OSError as e:
                status, detail = "FAIL", "unexpected %s: %s" % (
                    ename(e.errno), e)
            except Exception as e:
                status, detail = "FAIL", "%s: %s" % (type(e).__name__, e)
            dt = time.time() - t0
            sys.stdout.write("\r[ %s ] %-34s %6.2fs" % (status, name, dt))
            if detail:
                sys.stdout.write("  %s" % detail)
            sys.stdout.write("\n")
            sys.stdout.flush()
            if status == "PASS":
                npass += 1
            elif status == "SKIP":
                nskip += 1
            else:
                nfail += 1
                failures.append((name, detail))
    finally:
        if args.keep:
            print("\n-- leaving test data in %s" % root)
        else:
            shutil.rmtree(root, ignore_errors=True)
            if os.path.exists(root):
                print("\n-- warning: could not fully remove %s" % root)

    print("-" * 72)
    print("%d passed, %d failed, %d skipped in %.1fs"
          % (npass, nfail, nskip, time.time() - t_start))
    if failures:
        print("failed tests:")
        for name, detail in failures:
            print("  %-34s %s" % (name, detail))
    return 1 if nfail else 0


def _get_umask():
    u = os.umask(0o022)
    os.umask(u)
    return u


SELF = os.path.abspath(__file__)

if __name__ == "__main__":
    sys.exit(main())

