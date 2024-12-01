#define RPI_LEGACY_BASE             0xFFFFFFA0FE000000
#define RPI4_IO_MINI_UART_OFFSET    0x00215040
#define RPI4_MINI_UART_BASE         (RPI_LEGACY_BASE + RPI4_IO_MINI_UART_OFFSET)
#define PLAT_RPI_MINI_UART_BASE     RPI4_MINI_UART_BASE
#define RPI4_IO_PL011_UART_OFFSET   0x00201000
#define RPI4_PL011_UART_BASE        (RPI_LEGACY_BASE + RPI4_IO_PL011_UART_OFFSET)
#define PLAT_RPI_PL011_UART_BASE    RPI4_PL011_UART_BASE
#define PLAT_RPI_CRASH_UART_BASE    PLAT_RPI_PL011_UART_BASE

#define PL011_UARTFR_TXFF_BIT       5   /* Transmit FIFO full bit in UARTFR register */
#define UARTFR                      0x018
#define UARTDR                      0x000

#define UARTLSR                     0x14
#define UARTTX                      0x0
#define UARTLSR_TEMT                (1 << 6)	/* Tx Shift Register Empty */
#define UARTLSR_THRE                (1 << 5)	/* Tx Holding Register Empty */

#define ASCII_OFFSET_NUM	        0x30

	/*
	 * Helper macro to generate the best mov/movk combinations according
	 * the value to be moved. The 16 bits from '_shift' are tested and
	 * if not zero, they are moved into '_reg' without affecting
	 * other bits.
	 */
	.macro _mov_imm16 _reg, _val, _shift
		.if (\_val >> \_shift) & 0xffff
			.if (\_val & (1 << \_shift - 1))
				movk	\_reg, (\_val >> \_shift) & 0xffff, LSL \_shift
			.else
				mov	\_reg, \_val & (0xffff << \_shift)
			.endif
		.endif
	.endm

	/*
	 * Helper macro to load arbitrary values into 32 or 64-bit registers
	 * which generates the best mov/movk combinations. Many base addresses
	 * are 64KB aligned the macro will eliminate updating bits 15:0 in
	 * that case
	 */
	.macro mov_imm _reg, _val
		.if (\_val) == 0
			mov	\_reg, #0
		.else
			_mov_imm16	\_reg, (\_val), 0
			_mov_imm16	\_reg, (\_val), 16
			_mov_imm16	\_reg, (\_val), 32
			_mov_imm16	\_reg, (\_val), 48
		.endif
	.endm

	/* --------------------------------------------------------
	 * int console_pl011_core_putc(int c, uintptr_t base_addr)
	 * Function to output a character over the console. It
	 * returns the character printed on success or -1 on error.
	 * In : w0 - character to be printed
	 *      x1 - console base address
	 * Out : return -1 on error else return character.
	 * Clobber list : x2
	 * --------------------------------------------------------
	 */
    .global console_pl011_core_putc
    .text
console_pl011_core_putc:
#if ENABLE_ASSERTIONS
	cmp	x1, #0
	ASM_ASSERT(ne)
#endif /* ENABLE_ASSERTIONS */

	/* Prepend '\r' to '\n' */
	cmp	w0, #0xA
	b.ne	2f
1:
	/* Check if the transmit FIFO is full */
	ldr	w2, [x1, #UARTFR]
	tbnz	w2, #PL011_UARTFR_TXFF_BIT, 1b
	mov	w2, #0xD
	str	w2, [x1, #UARTDR]
2:
	/* Check if the transmit FIFO is full */
	ldr	w2, [x1, #UARTFR]
	tbnz	w2, #PL011_UARTFR_TXFF_BIT, 2b
	str	w0, [x1, #UARTDR]
	ret

	/* --------------------------------------------------------
	 * int console_16550_core_putc(int c, uintptr_t base_addr)
	 * Function to output a character over the console. It
	 * returns the character printed on success or -1 on error.
	 * In : w0 - character to be printed
	 *      x1 - console base address
	 * Out : return -1 on error else return character.
	 * Clobber list : x2
	 * --------------------------------------------------------
	 */
    .global console_16550_core_putc
    .text
console_16550_core_putc:
#if ENABLE_ASSERTIONS
	cmp	x1, #0
	ASM_ASSERT(ne)
#endif /* ENABLE_ASSERTIONS */

	/* Prepend '\r' to '\n' */
	cmp	w0, #0xA
	b.ne	2f
	/* Check if the transmit FIFO is full */
1:	ldr	w2, [x1, #UARTLSR]
	and	w2, w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	cmp	w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	b.ne	1b
	mov	w2, #0xD		/* '\r' */
	str	w2, [x1, #UARTTX]

	/* Check if the transmit FIFO is full */
2:	ldr	w2, [x1, #UARTLSR]
	and	w2, w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	cmp	w2, #(UARTLSR_TEMT | UARTLSR_THRE)
	b.ne	2b
	str	w0, [x1, #UARTTX]
	ret

    .global plat_crash_console_putc
    .text
plat_crash_console_putc:
	mov_imm	x1, PLAT_RPI_CRASH_UART_BASE
#if PLAT_RPI_CRASH_UART_BASE == PLAT_RPI_PL011_UART_BASE
	b	console_pl011_core_putc
#else
	b	console_16550_core_putc
#endif

/*
 * This function prints a string from address in x4.
 * In: x4 = pointer to string.
 * Clobber: x30, x0, x1, x2, x3
 */
    .global asm_print_str
    .text
asm_print_str:
	mov	x3, x30
1:
	ldrb	w0, [x4], #0x1
	cbz	x0, 2f
	bl	plat_crash_console_putc
	b	1b
2:
	ret	x3

/*
 * This function prints a hexadecimal number in x4.
 * In: x4 = the hexadecimal to print.
 * Clobber: x30, x0 - x3, x5
 */
    .global asm_print_hex
    .text
asm_print_hex:
	mov	x5, #64  /* No of bits to convert to ascii */

	/* Convert to ascii number of bits in x5 */
asm_print_hex_bits:
	mov	x3, x30
1:
	sub	x5, x5, #4
	lsrv	x0, x4, x5
	and	x0, x0, #0xf
	cmp	x0, #0xA
	b.lo	2f
	/* Add by 0x27 in addition to ASCII_OFFSET_NUM
	 * to get ascii for characters 'a - f'.
	 */
	add	x0, x0, #0x27
2:
	add	x0, x0, #ASCII_OFFSET_NUM
	bl	plat_crash_console_putc
	cbnz	x5, 1b
	ret	x3