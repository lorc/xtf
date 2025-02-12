include $(ROOT)/build/common.mk

ifneq ($(CONFIG_LIBAFL), y)
$(error "You need to enable CONFIG_LIBAFL via command line")
endif

NAME      := arm-vgic-fuzzer
CATEGORY  := fuzzer
TEST-ENVS := $(ALL_ENVIRONMENTS)

obj-perenv += main.o

include $(ROOT)/build/gen.mk
