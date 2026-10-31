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

/*
 * Hand-written assembly, the way glibc's string functions and OpenSSL's
 * primitives are, branching conditionally into another function: something
 * a compiler never does. `clamp` returns 0 for a negative or zero argument,
 * 100 for anything above 100, and the argument otherwise.
 */
__asm__(
    "	.text\n"
    "	.p2align 2\n"
    "	.type	clamp_zero, %function\n"
    "clamp_zero:\n"
    "	.cfi_startproc\n"
    "	mov	w0, #0\n"
    "	ret\n"
    "	.cfi_endproc\n"
    "	.size	clamp_zero, .-clamp_zero\n"
    "	.p2align 2\n"
    "	.type	clamp_hundred, %function\n"
    "clamp_hundred:\n"
    "	.cfi_startproc\n"
    "	mov	w0, #100\n"
    "	ret\n"
    "	.cfi_endproc\n"
    "	.size	clamp_hundred, .-clamp_hundred\n"
    "	.p2align 2\n"
    "	.globl	clamp\n"
    "	.type	clamp, %function\n"
    "clamp:\n"
    "	.cfi_startproc\n"
    "	tbnz	w0, #31, clamp_zero\n"
    "	cbz	w0, clamp_zero\n"
    "	cmp	w0, #100\n"
    "	b.gt	clamp_hundred\n"
    "	ret\n"
    "	.cfi_endproc\n"
    "	.size	clamp, .-clamp\n");
