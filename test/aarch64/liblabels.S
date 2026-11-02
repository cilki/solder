/*
 * A hand-written function the way OpenSSL's aarch64 MD5 is written: `sum` is
 * typed as a function but given no size, as `ossl_md5_block_asm_data_order`
 * is, and its loop starts at a plain label, `sum_loop`, which the assembler
 * keeps in .symtab as a local NOTYPE symbol like `ossl_md5_blocks_loop`. The
 * code after the loop reads `bias`, so a unit cut short at the label loses
 * that read as well as the loop. `next` follows with unwind info, as the C
 * functions after the MD5 assembly have. See test/README.md for how it is
 * built.
 */
	.text

	.globl	sum
	.type	sum, %function
sum:
	mov	x3, #0
sum_loop:
	ldr	w4, [x0], #4
	add	x3, x3, x4
	subs	x1, x1, #1
	b.ne	sum_loop
	adrp	x2, bias
	ldr	w4, [x2, #:lo12:bias]
	add	x0, x3, x4
	ret

	.globl	next
	.type	next, %function
next:
	.cfi_startproc
	add	x0, x0, #1
	ret
	.cfi_endproc
	.size	next, . - next

	.section .rodata
	.balign	4
	.type	bias, %object
bias:
	.word	7
	.size	bias, . - bias

	.section .note.GNU-stack, "", %progbits
