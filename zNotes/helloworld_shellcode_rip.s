;  code from course: http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
;  nasm -felf64 -g -F dwarf helloworld_shellcode_rip.s -o helloworld_shellcode_rip.o && ld helloworld_shellcode_rip.o -o helloworld_shellcode_rip
; 
DEFAULT REL
section .text
        global _start
_start:

shellcode:
        ;  x86_64  rdi rsi rdx r10 r8 r9
        xor rax, rax                    ; init to 0
        mov al, 1                       ; syscall # write

        ; size_t write(int fd, const void *buf, size_t count);

        mov rdi, rax                    ; std 1
        lea rsi, [hello_world]  ;
        xor rdx, rdx
        mov dl, 14                      ; # bytes
        syscall

_exit:
        xor rax, rax
        mov al, 60
        xor rdi, rdi
        syscall

        hello_world:    db      "Hello World!",0xa
