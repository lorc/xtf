#include <stdint.h>
#include <xtf/coverage.h>
#include <xtf/lib.h>
#include <xtf/report.h>
#include <xtf/hypercall.h>

#include <xtf/compiler.h>

static char coverage_data[521044 * 2];
static void base64_dump(const char *in, const int in_len);

int64_t coverage_get_size(void)
{
    int ret;

    xen_sysctl_t op =
    {
        .cmd = XEN_SYSCTL_coverage_op,
        .interface_version = xtf_probe_sysctl_interface_version(),
        .u.coverage_op = {
            .cmd = XEN_SYSCTL_COVERAGE_get_size,
            .size = 0,
        },
    };

    ret = hypercall_sysctl(&op);
    if (ret < 0) {
        printk("Error reading coverage size: %d\n", ret);
        return ret;
    }

    return op.u.coverage_op.size;
}

int coverage_read_data(void *buffer, uint32_t size)
{
    int ret;

    xen_sysctl_t op =
    {
        .cmd = XEN_SYSCTL_coverage_op,
        .interface_version = xtf_probe_sysctl_interface_version(),
        .u.coverage_op = {
            .cmd = XEN_SYSCTL_COVERAGE_read,
            .size = size,
            .buffer = {{ buffer }},
        },
    };

    ret = hypercall_sysctl(&op);
    if (ret < 0) {
        printk("Error reading coverage data: %d\n", ret);
    }

    return ret;
}

/* TODO: THIS IS A HACK Remove it and allocate buffer on a client's side */
void *coverage_get(int64_t *size)
{
    int ret;

    *size = coverage_get_size();

    if (*size < 0)
        return NULL;

    if ((size_t)*size > sizeof(coverage_data)) {
        printk("Xen coverage data is bigger than our buffer: %ld > %zi\n",
               *size, sizeof(coverage_data));
        return NULL;
    }

    ret = coverage_read_data(coverage_data, *size);
    if ( ret < 0 )
        return NULL;

    return coverage_data;
}

int coverage_dump(void)
{
    int64_t size = coverage_get_size();
    int ret = -EIO;

    if (size < 0)
        return size;

    if ((size_t)size > sizeof(coverage_data)) {
        printk("Xen coverage data is bigger than our buffer: %ld > %zi\n",
               size, sizeof(coverage_data));
        return -ENOMEM;
    }

    ret = coverage_read_data(coverage_data, size);
    if ( ret < 0 )
        return ret;

    printk("-----BEGIN XEN COVERAGE DATA-----\n");
    base64_dump(coverage_data, size);
    printk("-----END XEN COVERAGE DATA-----\n");

    return 0;

}
static const char *BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_emit_data(char data)
{
    static char line[100] __maybe_unused;
    const int line_len = 80;
    static int line_pos = 0;

    line[line_pos++] = data;

    if (line_pos == line_len || data == '\0')
    {
        line[line_pos] = '\0';
        printk("%s\n", line);
        line_pos = 0;
    }
}

static void base64_dump(const char *in, const int in_len)
{
    int in_index = 0;

    while (in_index < in_len) {
        // process group of 24 bit

        // first 6-bit
        base64_emit_data(BASE64[(in[in_index] & 0xFC) >> 2 ]);

        if ((in_index + 1) == in_len) {
            // padding case n.1
            //
            // Remaining bits to process are the right-most 2 bit of on the
            // last byte of input. we also need to add two bytes of padding
            base64_emit_data(BASE64[ ((in[in_index] & 0x3) << 4) ]);
            base64_emit_data('=');
            base64_emit_data('=');
            break;
        }

        // second 6-bit
        base64_emit_data(BASE64[ ((in[in_index] & 0x3) << 4) | ((in[in_index+1] & 0xF0) >> 4) ]);

        if ((in_index + 2) == in_len) {
            // padding case n.2
            //
            // Remaining bits to process are the right most 4 bit on the
            // last byte of input. We also need to add a single byte of
            // padding.
            base64_emit_data(BASE64[ ((in[in_index + 1] & 0xF) << 2) ]);
            base64_emit_data('=');
            break;
        }

        // third 6-bit
        base64_emit_data(BASE64[ ((in[in_index + 1] & 0xF) << 2) | ((in[in_index + 2] & 0xC0) >> 6) ]);

        // fourth 6-bit
        base64_emit_data(BASE64[ in[in_index + 2] & 0x3F ]);

        in_index += 3;
    }

    base64_emit_data('\0');
    return;
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
