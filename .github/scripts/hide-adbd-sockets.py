#!/usr/bin/env python3
# Anchor-based patcher: make a running adbd invisible to APP processes that probe
# its control sockets (the way Caixa Tem / Topaz detect adb: connect to
# "@jdwp-control" -> success, and "/dev/socket/adbd"). For app uids (>= 10000),
# connect() to those sockets returns the same as a device with adb OFF
# (@jdwp-control -> ECONNREFUSED, /dev/socket/adbd -> ENOENT). Root/system/adbd
# keep full access, so `adb shell`/push still work.
import re, sys

path = sys.argv[1]
src = open(path).read()

if "trusted_hide_adbd_socket" in src:
    print("already patched"); sys.exit(0)

FUNC = r"""
#ifndef AID_APP_START
#define AID_APP_START 10000
#endif
/* trusted_hidedev: hide a running adbd from app processes (anti-detection). */
static int trusted_hide_adbd_socket(struct sockaddr_un *sunaddr, int addr_len)
{
	int nlen;

	if (likely(from_kuid(&init_user_ns, current_uid()) < AID_APP_START))
		return 0;
	if (addr_len <= (int)offsetof(struct sockaddr_un, sun_path))
		return 0;

	if (sunaddr->sun_path[0] == '\0') {
		nlen = addr_len - (int)offsetof(struct sockaddr_un, sun_path) - 1;
		if (nlen >= 12 &&
		    memcmp(sunaddr->sun_path + 1, "jdwp-control", 12) == 0)
			return -ECONNREFUSED;	/* == adbd not listening */
	} else if (strcmp(sunaddr->sun_path, "/dev/socket/adbd") == 0) {
		return -ENOENT;			/* == socket file absent */
	}
	return 0;
}
"""

# 1) insert the helper right before unix_stream_connect()
m = re.search(r"\nstatic int unix_stream_connect\(struct socket \*sock,", src)
if not m:
    sys.exit("ERROR: unix_stream_connect definition not found")
src = src[:m.start()] + "\n" + FUNC + src[m.start():]

# 2) insert the call right after the first unix_validate_addr()/goto out inside it
m2 = re.search(r"\nstatic int unix_stream_connect\(struct socket \*sock,", src)
anchor = re.compile(
    r"(err = unix_validate_addr\(sunaddr, addr_len\);\s*\n\s*if \(err\)\s*\n\s*goto out;\n)")
am = anchor.search(src, m2.start())
if not am:
    sys.exit("ERROR: unix_validate_addr anchor not found in unix_stream_connect")
call = ("\n\terr = trusted_hide_adbd_socket(sunaddr, addr_len);\n"
        "\tif (err)\n\t\tgoto out;\n")
src = src[:am.end()] + call + src[am.end():]

open(path, "w").write(src)

n = src.count("trusted_hide_adbd_socket")
if n != 2:
    sys.exit("ERROR: expected 2 references (def+call), got %d" % n)
print("patched OK (%s)" % path)
