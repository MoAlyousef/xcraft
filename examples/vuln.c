// compile with:
// gcc -o bin/vuln examples/vuln.c -zexecstack -fno-stack-protector -no-pie -D_FORTIFY_SOURCE=0

#include <stdio.h>
#include <stdlib.h>

// just to get some gadgets in this small program.
void callme() {
    asm volatile("jmp %%rsp\n\t"
                 "pop %%rdi\n\t"
                 "ret"
                 :
                 :
                 : "rsp", "rdi");
}

int main(int argc, char **argv) {
    int pass = 0;
    char buf[80];
    puts("Enter pass");
    fflush(stdout);
    gets(buf);
    if (pass == 7478) {
        system("cat todo.txt");
    }
    if (argc == 0)
        callme();
}