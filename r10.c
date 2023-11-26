#include <stdio.h>

int main() {
    __asm__ volatile ("xchgq %r10, %r10");
    printf("xchg r10, r10 executed!\n");
    return 0;
}
