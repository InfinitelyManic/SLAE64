; David @InfinitelyManic
; jump call pop method
; code from course: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
section .bss
section .data
section .text
        global _start
_start:
        jmp short call_shellcode

shellcode:
        ;  x86_64        rdi   rsi   rdx   r10   r8    r9
        xor rax, rax            ; for sake of shellcode
        mov al, 1               ; syscall # write

        mov rdi, rax            ; std out = 1
        pop rsi                 ; string
        xor rdx, rdx            ; clear higher bits
        mov dl, 13              ; # bytes

        syscall

_exit:
        xor rax, rax
        mov al, 60
        syscall

call_shellcode:
        call shellcode
        hello_world:    db      `Hello World!`,0xa
