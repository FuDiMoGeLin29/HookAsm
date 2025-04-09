.CODE

Asm_Cmp PROC
		cmp rcx,rdx
		pushfq
		pop rax
		ret
Asm_Cmp ENDP

Asm_Test PROC
		test rcx,rdx
		pushfq
		pop rax
		ret
Asm_Test ENDP

END