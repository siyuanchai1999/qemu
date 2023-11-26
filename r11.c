#include <stdio.h>

int main() {
    __asm__ volatile ("xchgq %r11, %r11");
    printf("xchg r11, r11 executed!\n");
    return 0;
}
