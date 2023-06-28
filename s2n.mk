# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#

ifeq ($(PLATFORM),Darwin)
    LIBS = -lc -pthread
else ifeq ($(PLATFORM),FreeBSD)
    LIBS = -lthr
else ifeq ($(PLATFORM),NetBSD)
    LIBS = -pthread
else ifeq ($(PLATFORM),OpenBSD)
    LIBS = -pthread -lkvm
else
    LIBS = -pthread -ldl -lrt
endif

CRYPTO_LIBS = -lcrypto

CC	:= $(CROSS_COMPILE)$(CC)
CXX	:= $(CROSS_COMPILE)$(CXX)
AR	= $(CROSS_COMPILE)ar
RANLIB	= $(CROSS_COMPILE)ranlib
CLANG    ?= clang-3.9
LLVMLINK ?= llvm-link-3.9

SOURCES = $(wildcard *.c *.h)
CRUFT   = $(wildcard *.c~ *.h~ *.c.BAK *.h.BAK *.o *.a *.so *.dylib *.bc *.gcov *.gcda *.gcno *.info *.profraw *.tmp)
INDENT  = $(shell (if indent --version 2>&1 | grep GNU > /dev/null; then echo indent ; elif gindent --version 2>&1 | grep GNU > /dev/null; then echo gindent; else echo true ; fi ))

# BoringSSL is a C11 library and has less strict compiler flags than s2n. All other libcryptos use the default c99 flags
ifeq ($(S2N_LIBCRYPTO), boringssl)
	DEFAULT_CFLAGS = -std=c11
else ifeq ($(S2N_LIBCRYPTO), awslc)
	# AWS-LC is a BoringSSL derivative and has fixed the c11 issues but not all -Wcast-qual warnings
	DEFAULT_CFLAGS = -std=c99
else ifeq ($(S2N_LIBCRYPTO), awslc-fips)
	# AWS-LC is a BoringSSL derivative and has fixed the c11 issues but not all -Wcast-qual warnings
	DEFAULT_CFLAGS = -std=c99
else
	DEFAULT_CFLAGS = -std=c99 -Wcast-qual
endif

DEFAULT_CFLAGS += -pedantic -Wall -Werror -Wimplicit -Wunused -Wcomment -Wchar-subscripts -Wuninitialized \
                 -Wshadow  -Wcast-align -Wwrite-strings -fPIC -Wno-missing-braces\
                 -D_POSIX_C_SOURCE=200809L -O2 -I$(LIBCRYPTO_ROOT)/include/ \
                 -I$(S2N_ROOT)/api/ -I$(S2N_ROOT) -Wno-deprecated-declarations -Wno-unknown-pragmas -Wformat-security \
                 -D_FORTIFY_SOURCE=2 -fgnu89-inline -fvisibility=hidden -DS2N_EXPORTS

COVERAGE_CFLAGS = -fprofile-arcs -ftest-coverage
COVERAGE_LDFLAGS = --coverage
LDFLAGS = -z relro -z now -z noexecstack

FUZZ_CFLAGS = -fsanitize-coverage=trace-pc-guard -fsanitize=address,undefined,leak

# Define FUZZ_COVERAGE - to be used for generating coverage reports on fuzz tests
#                !!! NOT COMPATIBLE WITH S2N_COVERAGE !!!
ifeq ($(FUZZ_COVERAGE), true)
	FUZZ_CFLAGS += -fprofile-instr-generate -fcoverage-mapping
else
	ifeq ($(S2N_COVERAGE), true)
		DEFAULT_CFLAGS += ${COVERAGE_CFLAGS}
		LIBS += ${COVERAGE_LDFLAGS}
	endif
endif

ifdef FUZZ_TIMEOUT_SEC
	DEFAULT_CFLAGS += -DS2N_FUZZ_TESTING=1
endif

# Add a flag to disable stack protector for alternative libcs without
# libssp.
ifneq ($(NO_STACK_PROTECTOR), 1)
DEFAULT_CFLAGS += -Wstack-protector -fstack-protector-all
endif

ifeq ($(NO_INLINE), 1)
DEFAULT_CFLAGS += -fno-inline
endif

# Define S2N_TEST_IN_FIPS_MODE - to be used for testing when present.
ifdef S2N_TEST_IN_FIPS_MODE
    DEFAULT_CFLAGS += -DS2N_TEST_IN_FIPS_MODE
endif

# Don't compile PQ related source code
ifdef S2N_NO_PQ
	DEFAULT_CFLAGS += -DS2N_NO_PQ
endif

CFLAGS += ${DEFAULT_CFLAGS}

ifdef GCC_VERSION
	ifneq ("$(GCC_VERSION)","NONE")
		CC=gcc-$(GCC_VERSION)
		# Make doesn't support greater than checks, this uses `test` to compare values, then `echo $$?` to return the value of test's
		# exit code and finally uses the built in make `ifeq` to check if it was true and then adds the extra flag.
		ifeq ($(shell test $(GCC_VERSION) -gt 7; echo $$?), 0)
			CFLAGS += -Wimplicit-fallthrough
		endif

		ifeq ($(shell test $(GCC_VERSION) -ge 10; echo $$?), 0)
			CFLAGS += -fanalyzer
		endif
	endif
endif

DEBUG_CFLAGS = -g3 -ggdb -fno-omit-frame-pointer -fno-optimize-sibling-calls

ifdef S2N_ADDRESS_SANITIZER
	CFLAGS += -fsanitize=address -fuse-ld=gold -DS2N_ADDRESS_SANITIZER=1 ${DEBUG_CFLAGS}
endif

ifdef S2N_GDB
    S2N_DEBUG = 1
    CFLAGS += -O0
endif

ifdef S2N_DEBUG
	CFLAGS += ${DEBUG_CFLAGS}
endif

# Prepare CPPFLAGS by stripping out the unsupported options
CPPFLAGS = ${CFLAGS}
CPPFLAGS:=$(filter-out -Wimplicit,${CPPFLAGS})
CPPFLAGS:=$(filter-out -std=c99,${CPPFLAGS})
CPPFLAGS:=$(filter-out -fgnu89-inline,${CPPFLAGS})

# Prints more information when running tests
ifdef S2N_TEST_DEBUG
	DEFAULT_CFLAGS += -DS2N_TEST_DEBUG
endif

LLVM_GCOV_MARKER_FILE=${COVERAGE_DIR}/use-llvm-gcov.tmp

ifeq ($(S2N_UNSAFE_FUZZING_MODE),1)
    # Override compiler to clang if fuzzing, since gcc does not support as many sanitizer flags as clang
    CC=clang

    # Create a marker file so that later invocations of make can pick the right COV_TOOL by default
    $(shell touch "${LLVM_GCOV_MARKER_FILE}")

    # Turn on debugging and fuzzing flags when S2N_UNSAFE_FUZZING_MODE is enabled to give detailed stack traces in case
    # an error occurs while fuzzing.
    CFLAGS += ${DEFAULT_CFLAGS} ${DEBUG_CFLAGS} ${FUZZ_CFLAGS}

    # Filter out the visibility settings if we are fuzzing
    CFLAGS := $(filter-out -fvisibility=hidden,$(CFLAGS))
    CFLAGS := $(filter-out -DS2N_EXPORTS,$(CFLAGS))
    DEFAULT_CFLAGS := $(filter-out -fvisibility=hidden,$(DEFAULT_CFLAGS))
    DEFAULT_CFLAGS := $(filter-out -DS2N_EXPORTS,$(DEFAULT_CFLAGS))
    CPPFLAGS := $(filter-out -fvisibility=hidden,$(CPPFLAGS))
    CPPFLAGS := $(filter-out -DS2N_EXPORTS,$(CPPFLAGS))

endif

# Disable strict-prototypes check in clang
ifneq '' '$(findstring clang,$(CC))'
	CFLAGS += -Wno-strict-prototypes
	DEFAULT_CFLAGS += -Wno-strict-prototypes
	CPPFLAGS += -Wno-strict-prototypes
endif

# If COV_TOOL isn't set, pick a default COV_TOOL depending on if the LLVM Marker File was created.
ifndef COV_TOOL
	ifneq ("$(wildcard $(LLVM_GCOV_MARKER_FILE))","")
		COV_TOOL=llvm-gcov.sh
	endif
endif

# Used for testing.
prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
libdir ?= $(exec_prefix)/lib64
includedir ?= $(exec_prefix)/include

feature_probe = $(shell $(CC) $(CFLAGS) $(shell cat $(S2N_ROOT)/tests/features/GLOBAL.flags) $(shell cat $(S2N_ROOT)/tests/features/$(1).flags) -c -o tmp.o $(S2N_ROOT)/tests/features/$(1).c > /dev/null 2>&1 && echo "-D$(1)"; rm tmp.o > /dev/null 2>&1)

FEATURES := $(notdir $(patsubst %.c,%,$(wildcard $(S2N_ROOT)/tests/features/*.c)))
SUPPORTED_FEATURES := $(foreach feature,$(FEATURES),$(call feature_probe,$(feature)))
CFLAGS += $(SUPPORTED_FEATURES)
DEFAULT_CFLAGS += $(SUPPORTED_FEATURES)
CPPCFLAGS += $(SUPPORTED_FEATURES)

# only enable stacktraces if execinfo is available
ifneq ("$(call feature_probe,S2N_EXECINFO_AVAILABLE)","")
	CFLAGS += -DS2N_STACKTRACE
	DEFAULT_CFLAGS += -DS2N_STACKTRACE
	CPPCFLAGS += -DS2N_STACKTRACE
endif

CFLAGS_LLVM = ${DEFAULT_CFLAGS} -emit-llvm -c -g -O1

$(BITCODE_DIR)%.bc: %.c
	$(CLANG) $(CFLAGS_LLVM) -o $@ $< 


INDENTOPTS = -npro -kr -i4 -ts4 -nut -sob -l180 -ss -ncs -cp1

.PHONY : indentsource
indentsource:
	( for source in ${SOURCES} ; do ${INDENT} ${INDENTOPTS} $$source; done )

.PHONY : lcov
lcov: 
	lcov --capture --directory . --gcov-tool $(COV_TOOL) --output ./coverage.info


.PHONY : decruft
decruft:
	$(RM) -- ${CRUFT}
