#
# Component Makefile
#

COMPONENT_SRCDIRS := .

COMPONENT_ADD_INCLUDEDIRS := . include

COMPONENT_PRIV_INCLUDEDIRS := private_include

CFLAGS += \
	-fstrict-volatile-bitfields \
	-Wno-unused-function \
	-Wno-discarded-qualifiers \
	-Wno-unused-but-set-variable \
	-Wno-unused-value \
	-Wno-unused-variable \
	-Wno-cast-function-type \
	-DNDEBUG
