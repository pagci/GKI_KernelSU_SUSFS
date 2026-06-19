#!/usr/bin/env python3
# claydis SAFE rewrite of boot_config_proc_show: swap ONLY the verifiedbootstate
# value orange->green, emitting everything else byte-for-byte. No kstrdup, no
# memmove, no line dropping (the prior version did those and bootlooped). If the
# exact needle is absent, emit the buffer verbatim (no-op fallback) -> bootloop-safe.
import sys
f = sys.argv[1]
src = open(f).read()
sig = "static int boot_config_proc_show(struct seq_file *m, void *v)"
i = src.find(sig)
if i < 0:
    sys.exit("ERROR: boot_config_proc_show not found in " + f)
brace = src.find("{", i)
depth = 0
j = brace
while j < len(src):
    if src[j] == "{":
        depth += 1
    elif src[j] == "}":
        depth -= 1
        if depth == 0:
            break
    j += 1
end = j + 1
new_func = r'''static int boot_config_proc_show(struct seq_file *m, void *v)
{
	const char *p = saved_boot_config;
	const char *needle = "androidboot.verifiedbootstate = \"orange\"";
	const char *q;
	if (!p)
		return 0;
	q = strstr(p, needle);
	if (!q) {
		seq_puts(m, p);
		return 0;
	}
	seq_write(m, p, q - p);
	seq_puts(m, "androidboot.verifiedbootstate = \"green\"");
	seq_puts(m, q + strlen(needle));
	return 0;
}'''
src = src[:i] + new_func + src[end:]
if "#include <linux/string.h>" not in src:
    src = src.replace("#include <linux/slab.h>",
                      "#include <linux/slab.h>\n#include <linux/string.h>", 1)
open(f, "w").write(src)
print("patched boot_config_proc_show (safe verifiedbootstate->green) in " + f)
