/**
 * @file tests/arm-structured-fuzzer/main.c
 * @ref test-arm-structured-fuzzer
 *
 * @page test-arm-structured-fuzzer arm-structured-fuzzer
 *
 * @todo Docs for test-arm-structured-fuzzer
 *
 * @see tests/arm-structured-fuzzer/main.c
 */
#include <xtf.h>
#include <xtf/coverage.h>
#include <afl/libafl_qemu.h>
#define BUF_SIZE 4096

const char test_title[] = "Test arm-structured-fuzzer";
static uint8_t data[BUF_SIZE];

/*
 * Can't have malloc(), so use static buffers of sufficient size
 * We assume that fuzzer will not try to use buffers larger than 4k
 */
static uint8_t arg_buffers[5][4096];

extern void afl_hypercall(unsigned long arg0,
           unsigned long arg1,
           unsigned long arg2,
           unsigned long arg3,
           unsigned long arg4,
           unsigned long arg5,
           unsigned long op);

enum CmdTag {
    SetHvcArgVal = 1,
    SetHvcArgBuf = 2,
    Hvc = 3,
    FixupBufPtr = 4,
};

static uint8_t* advance(uint8_t **buf, unsigned int *len, size_t l)
{
    uint8_t* ret = *buf;
    (*buf) += l;
    (*len) -= l;

    return ret;
}

static void read(void* dst, uint8_t **buf, unsigned int *len, size_t l)
{
    memcpy(dst, advance(buf, len, l), l);
}

static void execute(uint8_t *buf, unsigned int len)
{
    uint64_t args[6];
    while (len)
    {
        uint8_t tag = *advance(&buf, &len, 1);

        switch(tag) {
        case SetHvcArgVal:
        {
            uint8_t arg_idx = *advance(&buf, &len, 1);
            read(args + arg_idx, &buf, &len, sizeof(args[0]));
            break;
        }
        case SetHvcArgBuf:
        {
            uint8_t arg_idx = *advance(&buf, &len, 1);
            uint64_t size;
            uint8_t *data;

            read(&size, &buf, &len, sizeof(size));
            data = arg_buffers[arg_idx];
            read(data, &buf, &len, size);
            args[arg_idx] = (uint64_t) data;
            break;
        }
        case Hvc:
        {
            uint64_t op;

            read(&op, &buf, &len, sizeof(op));
            afl_hypercall(args[0], args[1], args[2], args[3], args[4], args[5], op);
            break;
        }
        case FixupBufPtr:
        {
            uint8_t arg_idx = *advance(&buf, &len, 1);
            uint64_t offset;
            uint8_t *data;
            uint64_t *buf_ptr;
            read(&offset, &buf, &len, sizeof(offset));

            data = arg_buffers[arg_idx];
            /* Right now buf_ptr holds offset of real buffer relatively to `data` */
            buf_ptr = (uint64_t *)(data + offset);

            /* ... but Xen expects VA of the data buffer, so calculate it */
            *buf_ptr = (uint64_t)(data) + *buf_ptr;
            break;
        }
        }
    }
}

void test_main(void)
{
    uint64_t buf_size;
    int64_t cov_size;
    void *cov_ptr;

    lqprintf("LibAFL, hello from XTF-based structured harness!\n");

    libafl_qemu_test();

    buf_size = libafl_qemu_start_virt(data, BUF_SIZE);
    execute(data, buf_size);

    cov_ptr = coverage_get(&cov_size);
    if (cov_ptr) {
        libafl_qemu_xencov(cov_ptr, cov_size);
    }
    else{
        lqprintf("Failed to get XEN coverage data\n");
    }

    libafl_qemu_end(LIBAFL_QEMU_END_OK);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
