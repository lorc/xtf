CONFIG_LIBAFL := y

include $(ROOT)/build/common.mk

NAME      := arm-structured-fuzzer
CATEGORY  := fuzzer
TEST-ENVS := $(ALL_ENVIRONMENTS)
obj-perenv += main.o hyp.o

include $(ROOT)/build/gen.mk
