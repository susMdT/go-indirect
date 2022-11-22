TEXT ·GetPEB(SB), $0-8
     MOVQ 	0x60(GS), AX
     MOVQ	AX, ret+0(FP)
     RET

#define maxargs 16

TEXT ·Syscall(SB), $0-64
	XORQ AX,AX
	XORQ BX,BX

	MOVW callid+0(FP), AX
	MOVQ callfunc+8(FP), BX
	PUSHQ CX
	//put variadic size into CX
	MOVQ argh_len+24(FP),CX
	//put variadic pointer into SI
	MOVQ argh_base+16(FP),SI
	// SetLastError(0).
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)
	SUBQ	$(maxargs*8), SP	// room for args
	//no parameters, special case
	CMPL CX, $0
	JLE callz
	// Fast version, do not store args on the stack.
	CMPL	CX, $4
	JLE	loadregs
	// Check we have enough room for args.
	CMPL	CX, $maxargs
	JLE	2(PC)
	INT	$3			// not enough room -> crash
	// Copy args to the stack.
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI
loadregs:
	//move the stack pointer????? why????
	//ADDQ $8, SP
	// Load first 4 args into correspondent registers.
	MOVQ	0(SI), CX
	MOVQ	8(SI), DX
	MOVQ	16(SI), R8
	MOVQ	24(SI), R9

	MOVQ CX, R10
	CALL BX
	
	ADDQ	$((maxargs)*8), SP
	// Return result.
	POPQ	CX
	MOVL	AX, errcode+40(FP)
	RET
callz:
	//zero args means delicate stack stuff
	MOVQ CX, R10
	CALL BX
	ADDQ	$((maxargs+1)*8), SP
	MOVL	AX, errcode+40(FP)
	RET


