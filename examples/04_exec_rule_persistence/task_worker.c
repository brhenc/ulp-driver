/*
 * ulp-driver: ULP Example 4 - Execve Task Worker
 *
 * A program that is launched dynamically by users or scripts.
 * Demonstrates automatic in-kernel startup livepatching via execve rules.
 */

#include <stdio.h>
#include <stdlib.h>

static volatile int g_security_salt = 0;

/*
 * TARGET FUNCTION: check_security_status
 *
 * Requirements for persistent execve rules:
 * 1. __attribute__((noinline, noclone, aligned(16))): Guarantees the compiler
 *    generates an authentic function call and avoids interprocedural constant folding.
 * 2. In legacy code, returns 1 (Legacy / Insecure).
 * 3. When an in-kernel persistent rule is active, the kernel intercepts
 *    execve() before userspace starts and hotpatches the function to return 0.
 */
__attribute__((noinline, noclone, aligned(16)))
int check_security_status(void)
{
    int val = 1 + g_security_salt;
    __asm__ __volatile__("nop; nop; nop; nop; nop; nop; nop; nop;");
    return val;
}

int main(void)
{
    int status = check_security_status();
    printf("WORKER_STATUS: status=%d (%s)\n",
           status, (status == 0) ? "SECURED_BY_IN_KERNEL_RULE" : "LEGACY_UNPATCHED");
    return 0;
}
