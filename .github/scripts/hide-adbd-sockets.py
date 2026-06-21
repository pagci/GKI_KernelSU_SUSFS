#!/usr/bin/env python3
# Anti-detection: hide adbd's control sockets from app (uid>=10000) processes.
#
# Caixa Tem (Topaz/dfndr in libmcrypt.so) detects a running adbd by probing the
# UNIX sockets adbd creates, regardless of TCP port / firewall / spoofed props:
#   * "@jdwp-control" (abstract, SOCK_STREAM)  -> connect() succeeds when adbd runs
#   * "/dev/socket/adbd" (pathname, SOCK_DGRAM probe) -> EACCES (=exists) when adbd runs
# Both are resolved by unix_find_other(), the common helper used by
# unix_stream_connect(), unix_dgram_connect() and unix_dgram_sendmsg().
# Hooking it in ONE place makes both sockets look exactly like an adb-OFF device
# for app uids (@jdwp-control -> ECONNREFUSED, /dev/socket/adbd -> ENOENT), while
# root/system/adbd are untouched (adb shell/push and on-device adb keep working).
import re, sys

PATH = sys.argv[1]
src = open(PATH).read()

if "trusted_hide_adbd_find" in src:
    print("already patched"); sys.exit(0)

FUNC = '''#ifndef AID_APP_START
#define AID_APP_START 10000
#endif
/* anti-detection: make adbd's control sockets look absent to app processes */
static struct sock *trusted_hide_adbd_find(struct sockaddr_un *sunaddr, int addr_len)
{
\tint nlen;
\tif (likely(from_kuid(&init_user_ns, current_uid()) < AID_APP_START))
\t\treturn NULL;
\tif (addr_len <= (int)offsetof(struct sockaddr_un, sun_path))
\t\treturn NULL;
\tif (sunaddr->sun_path[0] == '\\0') {
\t\tnlen = addr_len - (int)offsetof(struct sockaddr_un, sun_path) - 1;
\t\tif (nlen >= 12 && memcmp(sunaddr->sun_path + 1, "jdwp-control", 12) == 0)
\t\t\treturn ERR_PTR(-ECONNREFUSED);
\t} else if (strcmp(sunaddr->sun_path, "/dev/socket/adbd") == 0) {
\t\treturn ERR_PTR(-ENOENT);
\t}
\treturn NULL;
}

'''

CALL = ('\tsk = trusted_hide_adbd_find(sunaddr, addr_len);\n'
        '\tif (sk)\n'
        '\t\treturn sk;\n\n')

# 1) insert FUNC right before the unix_find_other definition
m_def = re.search(r'\nstatic struct sock \*unix_find_other\(struct net \*net,', src)
if not m_def:
    print("ERROR: unix_find_other definition not found"); sys.exit(1)
ins = m_def.start() + 1  # after the leading newline
src = src[:ins] + FUNC + src[ins:]

# 2) insert CALL inside unix_find_other body, before the first `if (sunaddr->sun_path[0])`
m_def2 = re.search(r'\nstatic struct sock \*unix_find_other\(struct net \*net,', src)
body = src.find('{', m_def2.end())
m_anchor = re.search(r'\n\tif \(sunaddr->sun_path\[0\]\)', src[body:])
if not m_anchor:
    print("ERROR: unix_find_other body anchor not found"); sys.exit(1)
pos = body + m_anchor.start() + 1  # keep the leading newline before our block
src = src[:pos] + CALL + src[pos:]

open(PATH, "w").write(src)

n = src.count("trusted_hide_adbd_find")
if n != 2:
    print("ERROR: expected 2 references (def+call), got %d" % n); sys.exit(1)
print("patched OK (%s)" % PATH)
