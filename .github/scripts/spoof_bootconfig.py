#!/usr/bin/env python3
# claydis: rewrite /proc/bootconfig's show function so the verified-boot state
# is presented green WITHOUT a verification error, from the very first read.
# init (second-stage) imports /proc/bootconfig to set ro.boot.* props; making
# this output green means init writes the lock props natively -> NO resetprop
# (kills kknd "Modified Property (resetprop)" + Duck "raw property-area residue").
# Spaces (not tabs) are fine: C is whitespace-insensitive; no style-checker runs.
import sys

f = sys.argv[1]
src = open(f).read()
sig = "static int boot_config_proc_show(struct seq_file *m, void *v)"
i = src.find(sig)
if i < 0:
    sys.exit("ERROR: boot_config_proc_show not found in " + f)

# isolate the existing function body via brace matching
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

# raw string keeps the C escapes literal: '\n' (newline char lit), '\0', "\"orange\"" etc.
new_func = r'''static int boot_config_proc_show(struct seq_file *m, void *v)
{
    char *buf, *p, *nl, *o;
    if (!saved_boot_config)
        return 0;
    buf = kstrdup(saved_boot_config, GFP_KERNEL);
    if (!buf) {
        seq_puts(m, saved_boot_config);
        return 0;
    }
    p = buf;
    while (*p) {
        nl = strchr(p, '\n');
        if (nl)
            *nl = '\0';
        /* drop verification-error residue of a custom/unlocked boot */
        if (!strstr(p, "verifiedbooterror") && !strstr(p, "verifyerrorpart")) {
            /* present a clean verified-boot state */
            o = strstr(p, "\"orange\"");
            if (o) {
                memcpy(o, "\"green\"", 7);
                memmove(o + 7, o + 8, strlen(o + 8) + 1);
            }
            seq_puts(m, p);
            seq_putc(m, '\n');
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    kfree(buf);
    return 0;
}'''

src = src[:i] + new_func + src[end:]
if "#include <linux/string.h>" not in src:
    src = src.replace("#include <linux/slab.h>",
                      "#include <linux/slab.h>\n#include <linux/string.h>", 1)
open(f, "w").write(src)
print("patched boot_config_proc_show in " + f)
