#include <xtf/asm_macros.h>
#include <xen/xen.h>

ENTRY(afl_hypercall)
    mov x16, x6
    hvc XEN_HYPERCALL_TAG
    ret
ENDFUNC(afl_hypercall)

