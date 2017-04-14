; David @InfinitelyManic
; stack method
; code from course: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
section .text
        global _start
_start:

shellcode:
        ;  x86_64  rdi rsi rdx r10 r8 r9
        xor rax, rax                    ; init to 0
        mov al, 1                       ; syscall # write
        mov rdi, rax                    ; std 1

        ; rev <<< "Hello World" | xxd
        ;  646c 726f 5720 6f6c 6c65 48
        ;  646c726f 57206f6c6c65 48


        push 0x646c726f
        mov rbx, 0x57206f6c6c6548
        push rbx

        mov rsi, rsp
        xor rdx, rdx
        mov dl, 14                      ; # bytes
        syscall

_exit:
        xor rax, rax
        mov al, 60
        xor rdi, rdi
        syscall
