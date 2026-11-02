/*
 * Constant tables hand-written assembly keeps in .text, the way OpenSSL's
 * aarch64 code does: `consts` is typed as an object, as `_vpsm4_ex_consts`
 * is, and the table `untyped` reads has no symbol at all, only the `$d`
 * mapping symbol the assembler puts in front of it, like the SHA-256
 * constants ahead of `asm_aescbc_sha256_hmac`. Both are reached past their
 * first byte. Each table's words decode as branches and literal loads that
 * reach far outside the library, which is what scanning one as code made of
 * it. See test/README.md for how it is built.
 */
	.text

	.globl	typed
	.type	typed, %function
typed:
	adrp	x1, consts
	add	x1, x1, #:lo12:(consts + 16)
	ldr	w0, [x1, w0, uxtw #2]
	ret
	.size	typed, . - typed

	.balign	16
	.type	consts, %object
consts:
	.word	0x17ffffff	/* b    .-4 */
	.word	0x14ffffff	/* b    .+0x3fffffc */
	.word	0x58ffffe0	/* ldr  x0, .+0x1ffffc */
	.word	0x54ffffe0	/* b.eq .+0x1ffffc */
	.word	1, 2, 3, 4
	.size	consts, . - consts

	.globl	untyped
	.type	untyped, %function
untyped:
	adr	x1, .Ltable + 8
	ldr	w0, [x1, w0, uxtw #2]
	ret
	.size	untyped, . - untyped

	.balign	8
.Ltable:
	.word	0x94ffffff	/* bl   .+0x3fffffc */
	.word	0x18ffffe0	/* ldr  w0, .+0x1ffffc */
	.word	5, 6, 7, 8

	.section .note.GNU-stack, "", %progbits
