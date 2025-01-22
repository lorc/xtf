/**
 * @file tests/arm-hypercall-fuzzer/main.c
 * @ref test-arm-hypercall-fuzzer
 *
 * @page test-arm-hypercall-fuzzer arm-hypercall-fuzzer
 *
 * @todo Docs for test-arm-hypercall-fuzzer
 *
 * @see tests/arm-hypercall-fuzzer/main.c
 */
#include <xtf.h>
#include <afl/libafl_qemu.h>
#define BUF_SIZE 4096

const char test_title[] = "Test arm-hypercall-fuzzer";
static char data[BUF_SIZE];

extern void afl_hypercall(unsigned long arg0,
		   unsigned long arg1,
		   unsigned long arg2,
		   unsigned long arg3,
		   unsigned long arg4,
		   unsigned long arg5,
		   unsigned long op);

/* Fuzz HVC arguments only */
static void fuzz_hypercall_regs(char *buf, int len)
{
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
	unsigned long arg4;
	unsigned long arg5;
	unsigned long op;

	memcpy(&op, buf, sizeof(op));
	buf += sizeof(op);
	memcpy(&arg0, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);
	memcpy(&arg1, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);
	memcpy(&arg2, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);
	memcpy(&arg3, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);
	memcpy(&arg4, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);
	memcpy(&arg5, buf, sizeof(unsigned long));
	buf += sizeof(unsigned long);

	afl_hypercall(arg0, arg1, arg2, arg3, arg4, arg5, op);
}

/* Content-aware fuzzers */

static void fuzz_sched_op_compat(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_sched_op_compat;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);
}

static void fuzz_platform_op(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_platform_op;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_memory_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_memory_op;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);
}

static void fuzz_multicall(char *buf, int len)
{
	/* 0 - buf */
	/* 1 - cnt */
	unsigned long op = __HYPERVISOR_multicall;
	unsigned long cnt;
	unsigned long arg;

	memcpy(&cnt, buf, sizeof(cnt));
	buf += sizeof(cnt);
	arg = (unsigned long)buf;
	afl_hypercall(arg, cnt, 0, 0, 0, 0, op);
}

static void fuzz_event_channel_op_compat(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_platform_op;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_xen_version(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_xen_version;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);
}

static void fuzz_console_io(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - count */
	/* 2 - buf */
	unsigned long op = __HYPERVISOR_console_io;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);


	arg = (unsigned long)buf;
	afl_hypercall(cmd, len, arg, 0, 0, 0, op);
}

static void fuzz_physdev_op_compat(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_physdev_op_compat;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_grant_table_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	/* 2 - count */
	unsigned long op = __HYPERVISOR_grant_table_op;
	unsigned long cmd;
	unsigned long arg;
	unsigned long cnt;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);

	memcpy(&cnt, buf, sizeof(cnt));
	buf += sizeof(cnt);


	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, cnt, 0 ,0 ,0, op);
}

static void fuzz_vm_assist(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - type */
	unsigned long op = __HYPERVISOR_vm_assist;
	unsigned long cmd;
	unsigned long type;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);

	memcpy(&type, buf, sizeof(type));
	buf += sizeof(type);

	afl_hypercall(cmd, type, 0, 0, 0, 0, op);
}

static void fuzz_vcpu_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - vcpuid */
	/* 2 - buf */
	unsigned long op = __HYPERVISOR_vcpu_op;
	unsigned long cmd;
	unsigned long arg;
	unsigned long vcpu;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);

	memcpy(&vcpu, buf, sizeof(vcpu));
	buf += sizeof(vcpu);


	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, vcpu,0, 0, 0, op);
}

static void fuzz_xsm_op(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_xsm_op;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_sched_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_sched_op;;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);
}

static void fuzz_event_channel_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_event_channel_op;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);

}

static void fuzz_physdev_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_physdev_op;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);

}

static void fuzz_hvm_op(char *buf, int len)
{
	/* 0 - cmd */
	/* 1 - buf */
	unsigned long op = __HYPERVISOR_hvm_op;
	unsigned long cmd;
	unsigned long arg;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	arg = (unsigned long)buf;
	afl_hypercall(cmd, arg, 0, 0, 0, 0, op);

}

static void fuzz_sysctl(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_sysctl;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_domctl(char *buf, int len)
{
	/* 0 - buf */
	unsigned long op = __HYPERVISOR_domctl;
	unsigned long arg;

	arg = (unsigned long)buf;
	afl_hypercall(arg,0, 0, 0, 0, 0, op);
}

static void fuzz_dm_op(char *buf, int len)
{
	/* 0 - domid */
	/* 1 - nr bufs */
	/* 2 - buffs */
	unsigned long op = __HYPERVISOR_grant_table_op;
	unsigned long cmd;
	unsigned long arg;
	unsigned long cnt;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);

	memcpy(&cnt, buf, sizeof(cnt));
	buf += sizeof(cnt);


	arg = (unsigned long)buf;
	afl_hypercall(cmd, cnt, arg, 0, 0, 0, op);
}

static void fuzz_hypfs_op(char *buf, int len)
{
	/* 0 - cmd  */
	/* 1 - buf1 */
	/* 2 - arg2 */
	/* 3 - buf2  */
	/* 4 - arg4  */
	unsigned long op = __HYPERVISOR_grant_table_op;
	unsigned long cmd;
	unsigned long buf1;
	unsigned long buf2;
	unsigned long arg1;
	unsigned long arg2;

	memcpy(&cmd, buf, sizeof(cmd));
	buf += sizeof(cmd);
	len -= sizeof(cmd);

	memcpy(&arg1, buf, sizeof(arg1));
	buf += sizeof(arg1);
	len -= sizeof(arg1);

	memcpy(&arg2, buf, sizeof(arg2));
	buf += sizeof(arg2);
	len -= sizeof(arg2);

	buf1 = (unsigned long)buf;

	if (len > 1)
		buf2 = (unsigned long)buf + len/2;
	else
		buf2 = 0;
	afl_hypercall(cmd, buf1, arg1, buf2, arg2, 0, op);
}

static void (*hypercall_fuzz[])(char *buf, int len)  =
{
	fuzz_hypercall_regs,
	fuzz_sched_op_compat,
	fuzz_platform_op,
	fuzz_memory_op,
	fuzz_multicall,
	fuzz_event_channel_op_compat,
	fuzz_xen_version,
	fuzz_console_io,
	fuzz_physdev_op_compat,
	fuzz_grant_table_op,
	fuzz_vm_assist,
	fuzz_vcpu_op,
	fuzz_xsm_op,
	fuzz_sched_op,
	fuzz_event_channel_op,
	fuzz_physdev_op,
	fuzz_hvm_op,
	fuzz_sysctl,
	fuzz_domctl,
	fuzz_dm_op,
	fuzz_hypfs_op,
};

/* Dispatcher function */
static void fuzz_hypercalls(char *buf, int len)
{
	char idx = buf[0];

	hypercall_fuzz[idx % ARRAY_SIZE(hypercall_fuzz)](buf + 1, len - 1);
}

void test_main(void)
{
 	uint64_t buf_size;
	data[0] = 0xff;  // init page

	lqprintf("LibAFL, hello from XTF-based test harness!\n");

	libafl_qemu_test();

	memset(data, 0, sizeof(data));

	buf_size = libafl_qemu_start_virt(data, BUF_SIZE);
	fuzz_hypercalls(data, buf_size);
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
