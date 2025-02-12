/**
 * @file tests/arm-vgic-fuzzer/main.c
 * @ref test-arm-vgic-fuzzer
 *
 * @page test-arm-vgic-fuzzer arm-vgic-fuzzer
 *
 * @todo Docs for test-arm-vgic-fuzzer
 *
 * @see tests/arm-vgic-fuzzer/main.c
 */
#include <xtf.h>
#include <arch/gic.h>
#include <arch/io.h>
#include <arch/mm.h>
#include <afl/libafl_qemu.h>

#define BUF_SIZE 4096

const char test_title[] = "Test arm-vgic-fuzzer";
static char data[BUF_SIZE];

/* We want fuzzer to generate many different access types */
struct mmio_access {
    void* addr;
    uint64_t data;
    bool    read;              /* true for read, false for write */
    char    size;              /* 0 for 8 bit, 1 for 16 bit, etc... */
};

static size_t fill_access(struct mmio_access* access, const char *buf,
                          size_t len, void *base_addr)
{
    char access_cfg = buf[0];
    uint16_t offset;
    size_t pos = 1;

    if ( pos >= len )
        return 0;

    access->read = (bool)(access_cfg & 1);
    access->size = (access_cfg >> 1) & 3;

    memcpy(&offset, buf + pos, sizeof(offset));
    pos += sizeof(offset);

    access->addr = base_addr + offset;

    /* there are no 16-bit accesses */
    if (access->size == 1)
        access->size = 2;

    switch (access->size)
    {
    case 0:
    {
        uint8_t data;
        if ( pos + sizeof(data) > len )
            return 0;
        memcpy(&data, buf + pos, sizeof(data));
        access->data = data;
        pos += sizeof(data);
        break;
    }
    case 2:
    {
        uint32_t data;
        if ( pos + sizeof(data) > len )
            return 0;
        memcpy(&data, buf + pos, sizeof(data));
        access->data = data;
        pos += sizeof(data);
        break;
    }
    case 3:
    {
        uint64_t data;
        if ( pos + sizeof(data) > len )
            return 0;
        memcpy(&data, buf + pos, sizeof(data));
        access->data = data;
        pos += sizeof(data);
        break;
    }
    }

    return pos;
}

/* "volatile" to prevent compiler optimization */
volatile uint64_t io_data;

static void perform_access(const struct mmio_access *access)
{
    if (access->read)
    {
        switch (access->size)
        {
        case 0:
            io_data = io_readb(access->addr);
            break;
        case 2:
            io_data = io_readl(access->addr);
            break;
        case 3:
            io_data = io_readq(access->addr);
            break;
        default:
            /* Should not be here */
            ASSERT(0);
        }
    }
    else
    {
        switch (access->size)
        {
        case 0:
            io_writeb((uint8_t)access->data, access->addr);
            break;
        case 2:
            io_writel((uint32_t)access->data, access->addr);
            break;
        case 3:
            io_writeq((uint64_t)access->data, access->addr);
            break;
        default:
            /* Should not be here */
            ASSERT(0);
        }
    }
}

#if defined(CONFIG_GICV3)

static void *gicv3_dist;
static void *gicv3_rdist;
static void *gicv3_rdist_sgi;

static void *gic_get_base_addr(char info)
{
        switch (info >> 6 )
        {
        case 0:
        case 3:
            return gicv3_dist;
        case 1:
            return gicv3_rdist;
        case 2:
            return gicv3_rdist_sgi;
        }
        ASSERT(0);
}

#elif defined(CONFIG_GICV2)

static void *gicv2_dist;
static void *gicv2_cpu;

static void *gic_get_base_addr(char info)
{
        switch (info >> 7 )
        {
        case 0:
            return gicv2_dist;
        case 1:
            return gicv2_cpu;
        }
        ASSERT(0);
}

#else
#error "Unknown GIC version"
#endif

static void fuzz_gic(char *buf, size_t len)
{
    struct mmio_access access;

    int64_t slen = len;

    while (slen >= 0)
    {
        void *base_addr;
        size_t sz;
        /*
         * We use high bits it buf[0] to select GIC region
         * and low bits to determine access size and direction.
         */
        base_addr = gic_get_base_addr(buf[0]);

        sz = fill_access(&access, buf, slen, base_addr);
        if (!sz)
            break;
        buf += sz;
        slen -= sz;

        perform_access(&access);
    }
}


void test_main(void)
{
    uint64_t buf_size;

    lqprintf("Starting vGIC fuzzer\n");

#if defined(CONFIG_GICV3)
    gicv3_dist = get_fixmap(FIXMAP_GICD, CONFIG_GICV3_DIST_ADDRESS);
    gicv3_rdist = get_fixmap(FIXMAP_GICR, CONFIG_GICV3_RDIST_ADDRESS);
    gicv3_rdist_sgi = get_fixmap(FIXMAP_GICS,
                                 CONFIG_GICV3_RDIST_ADDRESS +
                                 GICR_SGI_BASE_OFF);

    lqprintf("gicv3_dist is at %p\n", gicv3_dist);
    lqprintf("gicv3_rdist is at %p\n", gicv3_rdist);
    lqprintf("gicv3_rdist_sgi is at %p\n", gicv3_rdist_sgi);
#else
    gicv2_dist = (char *)get_fixmap(FIXMAP_GICD, CONFIG_GICV2_DIST_ADDRESS);
    gicv2_cpu = (char *)get_fixmap(FIXMAP_GICC, CONFIG_GICV2_CPU_ADDRESS);
    lqprintf("gicv2_dist is at %p\n", gicv2_dist);
    lqprintf("gicv2_cpu is at %p\n", gicv2_cpu);
#endif

    libafl_qemu_test();

    buf_size = libafl_qemu_start_virt(data, BUF_SIZE);

    fuzz_gic(data, buf_size);

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
