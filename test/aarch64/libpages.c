/*
 * The aarch64 reference forms the extractor has to find: `adrp` pairs, a
 * branch to a local helper, and a call through the PLT. Built with
 * -fno-section-anchors so that each object is reached by its own address;
 * see test/README.md for the command.
 */
#include <stdio.h>

static int counter;                     /* .bss, read and written */
static int table[4] = {1, 2, 3, 4};     /* .rodata: nothing writes it */
static const char banner[] = "solder";  /* .rodata */

/* A local helper nothing exports: reached by a direct `b`. */
static __attribute__((noinline)) int helper(int x)
{
    return table[x & 3] + counter;
}

/* One adrp shared by the load and the store of `counter`. */
int bump(int x)
{
    counter += x;
    return helper(x);
}

/* A call through the PLT, and the address of a string. */
int shout(void)
{
    return puts(banner);
}
