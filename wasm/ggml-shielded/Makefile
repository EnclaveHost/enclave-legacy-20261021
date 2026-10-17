# shielded ggml backend -- the TEE-side half that lets an ordinary ggml graph
# offload its linear ops to an untrusted GPU.
#
# Built standalone here so the field/wire/tee layers can be tested without the
# engine; the backend object is what gets linked into the ELL build.

CC      ?= cc
# -fno-math-errno is an ABI guard, not an optimisation: without it gcc emits a
# call to libm's sqrtf for 1/sqrt(mean+eps) in shielded-fusion.h, and a builder
# on glibc >= 2.43 binds it to sqrtf@GLIBC_2.43 - a version node older guests
# (the metal engine image) do not define, so the .so fails to dlopen there.
# Inlined as sqrtss it references nothing and rounds identically, which the
# byte-exact field encoder needs. metal/build-image.mjs mirrors this and
# fails the build if the result would not load in the guest.
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -fno-math-errno
LDLIBS  += -lm

CORE_SRC := shielded-field.c shielded-wire.c shielded-tee.c shielded-parwork.c shielded-pads.c shielded-bank.c shielded-http.c prefix-kv.c tweetnacl.c poly1305-donna.c
CORE_OBJ := $(CORE_SRC:.c=.o) shielded-simd-avx512.o shielded-simd-generic.o
# The dealer's build of the trusted half is the ONLY one carrying the zero-pad
# mint path (SHIELDED_DEALER_MODE: r goes to the dealer's own worker in the
# clear). Production and phone builds compile without it, so no env can turn
# it on there.
DEALER_OBJ := $(CORE_SRC:.c=.dealer.o) shielded-simd-avx512.o shielded-simd-generic.o
%.dealer.o: %.c
	$(CC) $(CFLAGS) -DSHIELDED_DEALER_MODE -c $< -o $@
shielded-field.dealer.o: CFLAGS += -ffp-contract=off
LDLIBS   += -lpthread

# The field encoder must not be contracted into FMAs: the worker runs the same
# source and both sides have to round identically.
shielded-field.o: CFLAGS += -ffp-contract=off

# The ggml backend needs ggml's headers and libraries. They are NOT a build
# dependency of the core above, on purpose: the field/wire/tee layers are what
# the reference can be checked against, and they must stay testable on a machine
# with no engine checkout at all (CI is one).
GGML_SRC ?= $(HOME)/Projects/llama.cpp
GGML_LIB ?= $(HOME)/Projects/llamacpp-lib
GGML_INC := -I$(GGML_SRC)/ggml/include -I$(GGML_SRC)/ggml/src
CXX      ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -fPIC -fno-math-errno

all: shielded-probe field-selftest prepare-selftest half-selftest refill-selftest dealt-selftest spill-selftest pads-unbox pads-keygen prefix-kv-selftest postmortem-selftest

shielded-tee.o shielded-tee.dealer.o: shielded-tee.h shielded-mint-balance.h
shielded-tee.o shielded-tee.dealer.o: shielded-pad-mint-v3.h shielded-pad-mint-v3.inc shielded-pads-v3.h shielded-pad-manifest.h shielded-pad-layout.h
shielded-tee.o shielded-tee.dealer.o: shielded-parwork.h
shielded-tee.o shielded-tee.dealer.o: shielded-spill.h shielded-spill.inc
shielded-parwork.o: shielded-parwork.h
shielded-pads.o shielded-pads.dealer.o: shielded-pads-v3.inc shielded-pads-v3.h shielded-pad-sparse-table.h shielded-pad-manifest.h shielded-pad-layout.h

# Built only where an engine checkout exists; `make ggml` opts in.
ggml: ggml-test

# Whole-model runner; needs libllama as well as ggml.
run: shielded-run

# The calibrator: any q8_0 GGUF libllama can prefill -> its .calib for the C
# backend. Needs libllama too. Against an ELL engine drop (no source checkout)
# point the include and lib variables at it:
#   make calib GGML_LIB=$ELL/lib LLAMA_INC=-I$ELL_HDR/include GGML_INC=-I$ELL_HDR/ggml-include
#   ./shielded-calib --backend $ELL/lib/libggml-cpu.so model.gguf model.calib
# Use the pinned engine's headers and libenclave_llama/libmtmd as well. For an
# MTP vision bundle, pass --mtp --mmproj mmproj-F16.gguf --image public.png.
# Set LD_LIBRARY_PATH=$ELL/lib when its libraries are outside the system path.
calib: shielded-calib
LLAMA_INC ?= -I$(GGML_SRC)/include

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# The hot loops, twice: the AVX-512 VNNI build and the one that runs anywhere.
# shielded-tee.c checks them against each other before trusting the fast one.
shielded-simd-avx512.o: shielded-simd.c shielded-simd.h shielded-field.h
	$(CC) $(CFLAGS) -O3 -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vnni -DSH_SIMD_AVX512 -c $< -o $@
shielded-simd-generic.o: shielded-simd.c shielded-simd.h shielded-field.h
	$(CC) $(CFLAGS) -O3 -c $< -o $@

shielded-probe: shielded-probe.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

field-selftest: field-selftest.c shielded-field.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

prepare-selftest: prepare-selftest.c shielded-field.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

half-selftest: half-selftest.c shielded-field.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# The refill kernels against a scalar exact product (exit 77 = no AVX-512 VNNI here).
refill-selftest: refill-selftest.c shielded-simd-avx512.o shielded-field.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Dealt pads end to end on synthetic weights: mint, read back against an
# exact oracle, tamper, exhaustion, ledger window, the link's own import.
dealt-selftest: dealt-selftest.c $(DEALER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Keyed pads (format 4, shielded/dealer/HOST-BANK.md): host-bank cells with their own mask keys.
pads-bank: pads-bank.c $(DEALER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
keyed-bank-fixture: keyed-bank-fixture.c $(DEALER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
keyed-selftest: keyed-selftest.c $(DEALER_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Node<->C interop helpers for dealt pads (test/pads-interop.test.mjs).
pads-unbox: pads-unbox.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
bank-probe: bank-probe.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)
shielded-soak: shielded-soak.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

postmortem-selftest: postmortem-selftest.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# The pad spill's store (shielded-spill.h): round trips, and the host's moves
# (replay, move, corrupt) refused. Needs a directory that takes O_DIRECT.
spill-selftest: spill-selftest.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# ...and end to end through a worker: idle fill, a burst wider than the ring,
# refill, and a wiped disk. SHIELDED_WORKER=host:port ./spill-link-selftest DIR
spill-link-selftest: spill-link-selftest.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

prefix-kv-selftest: prefix-kv-selftest.c prefix-kv.o shielded-pads.o tweetnacl.o poly1305-donna.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

pads-keygen: pads-keygen.c $(CORE_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

ggml-shielded.o: ggml-shielded.cpp ggml-shielded.h shielded-fusion.h shielded-group-key.h shielded-latency.h shielded-tee.h shielded-spill.h shielded-field.h shielded-simd.h shielded-source-bytes.h shielded-source-prefetch.h
	$(CXX) $(CXXFLAGS) $(GGML_INC) -c $< -o $@

ggml-test: ggml-test.cpp ggml-shielded.o $(CORE_OBJ)
	$(CXX) $(CXXFLAGS) $(GGML_INC) -o $@ $^ \
	  -L$(GGML_LIB) -lggml -lggml-base -lggml-cpu $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

# SHIELDED_EXTRA_DEFS is for a BENCH build and nothing else. The only define
# it is meant to carry is -DSHIELDED_ALLOW_DEV_SHM_RINGS, which lets the ring
# live under /dev/shm on a box that has no CVM ring directory. Production
# builds pass nothing here and keep the single root-owned ring path.
SHIELDED_EXTRA_DEFS ?=
ggml-shielded-dl.o: ggml-shielded.cpp ggml-shielded.h shielded-fusion.h shielded-group-key.h shielded-compact.h shielded-latency.h shielded-tee.h shielded-spill.h shielded-field.h shielded-simd.h shielded-source-bytes.h shielded-source-prefetch.h
	$(CXX) $(CXXFLAGS) -DGGML_BACKEND_DL -DGGML_BACKEND_SHARED $(SHIELDED_EXTRA_DEFS) $(COMPACT_DEFS) $(GGML_INC) -c $< -o $@

libggml-shielded.so: ggml-shielded-dl.o $(CORE_OBJ)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ -L$(GGML_LIB) -lggml-base $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

ggml-shielded-dealer.o: ggml-shielded.cpp ggml-shielded.h shielded-fusion.h shielded-group-key.h shielded-latency.h shielded-tee.h shielded-spill.h shielded-field.h shielded-simd.h shielded-source-bytes.h shielded-source-prefetch.h
	$(CXX) $(CXXFLAGS) -DGGML_BACKEND_DL -DGGML_BACKEND_SHARED -DSHIELDED_DEALER_MODE $(GGML_INC) -c $< -o $@
libggml-shielded-dealer.so: ggml-shielded-dealer.o $(DEALER_OBJ)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ -L$(GGML_LIB) -lggml-base $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

shielded-run: shielded-run.cpp libggml-shielded.so prefix-kv.o shielded-pads.o tweetnacl.o poly1305-donna.o
	$(CXX) $(CXXFLAGS) -I$(GGML_SRC)/include $(GGML_INC) -o $@ $< prefix-kv.o shielded-pads.o tweetnacl.o poly1305-donna.o \
	  -L$(GGML_LIB) -lllama -lggml -lggml-base -ldl $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

# The platform's shared-prefix service, offline (prefix-kv.h): prefill in the
# clear, save the sequence state, sign the sidecar. No shielded backend.
prefix-kv-mint: prefix-kv-mint.cpp prefix-kv.o shielded-pads.o tweetnacl.o poly1305-donna.o
	$(CXX) $(CXXFLAGS) -I$(GGML_SRC)/include $(GGML_INC) -o $@ $^ \
	  -L$(GGML_LIB) -lllama -lggml -lggml-base -ldl $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

# shielded-field.o is the SAME object the backend links, -ffp-contract=off and
# all: the calibrator's w_fixed must be the runtime's, byte for byte, or the
# exponent it picks is for a product the runtime never forms.
shielded-calib: shielded-calib.cpp shielded-field.o shielded-field.h ../llama-shim/enclave_llama.h
	$(CXX) $(CXXFLAGS) $(LLAMA_INC) $(GGML_INC) -o $@ shielded-calib.cpp shielded-field.o \
	  -L$(GGML_LIB) -lenclave_llama -lllama -lggml -lggml-base $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

# Exchange-count amortiser benches (`make bench`): the same link line as
# shielded-run, backend modules loaded by path at run time (BACKENDS env), so
# cpu / cuda / shielded rows come from identical engine code.
#   bench-batch  ms per decode step of M rows (a verify pass of K=M-1 drafts,
#                or M concurrent users): the batch-width cost curve.
#   bench-spec   real MTP self-drafting speculation through libenclave_llama's
#                own verbs (draft2 / decode_seq_full / rewind / harvest).
bench: bench-batch bench-spec

# The dealer: mint .pads shipments from a model; libllama for the load, the
# backend module for the registration and the mint (shielded/dealer/PLAN.md).
shielded-dealer: shielded-dealer.cpp shielded-dealer-stream.h $(DEALER_OBJ)
	$(CXX) $(CXXFLAGS) $(LLAMA_INC) $(GGML_INC) -I../llama-shim -o $@ $< $(DEALER_OBJ) \
	  -L$(GGML_LIB) -lllama -lggml -lggml-base -ldl $(LDLIBS) -Wl,-rpath,$(GGML_LIB)

bench-batch: bench-batch.cpp
	$(CXX) $(CXXFLAGS) -I$(GGML_SRC)/include $(GGML_INC) -o $@ $< \
	  -L$(GGML_LIB) -lllama -lggml -lggml-base -ldl -Wl,-rpath,$(GGML_LIB)

bench-spec: bench-spec.cpp ../llama-shim/enclave_llama.h
	$(CXX) $(CXXFLAGS) -I$(GGML_SRC)/include $(GGML_INC) -I../llama-shim -o $@ $< \
	  -L$(GGML_LIB) -lenclave_llama -lllama -lggml -lggml-base -ldl -Wl,-rpath,$(GGML_LIB)

clean:
	rm -f $(CORE_OBJ) shielded-compact.o ggml-shielded-dl.o shielded-probe field-selftest prepare-selftest half-selftest refill-selftest dealt-selftest spill-selftest spill-link-selftest pads-unbox pads-keygen ggml-shielded.o ggml-test shielded-run shielded-calib libggml-shielded.so bench-batch bench-spec

.PHONY: all clean ggml run calib bench

# Opt-in measured x86 production candidate. Default builds have no new library
# dependency. The release builder pins the oneDNN/OpenMP closure explicitly.
ifneq ($(SHIELDED_COMPACT_ROOT),)
COMPACT_DEFS := -DSHIELDED_COMPACT
COMPACT_LIBDIR := $(SHIELDED_COMPACT_ROOT)/usr/lib
libggml-shielded.so: shielded-compact.o shielded-source-store.o
LDLIBS += -L$(COMPACT_LIBDIR) -ldnnl -lgomp
shielded-source-store.o: shielded-source-store.cpp shielded-source-store.h shielded-source-quant.h
	$(CXX) $(CXXFLAGS) -ffp-contract=off $(GGML_INC) -I$(SHIELDED_COMPACT_ROOT)/usr/include -O3 -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vnni -c $< -o $@
shielded-compact.o: shielded-compact.cpp shielded-compact.h
	$(CXX) $(CXXFLAGS) -I$(SHIELDED_COMPACT_ROOT)/usr/include -O3 -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vnni -c $< -o $@
endif

# The diffusion sibling of shielded-calib (sd-calib.cpp): stable-diffusion.cpp's
# eval callback instead of libllama's. Host tool, shipped nowhere. Build against
# the SAME ggml the runtime's stable-diffusion.cpp links (SD_SRC / SD_LIB).
SD_SRC ?= $(HOME)/Projects/sd.cpp
SD_LIB ?= $(SD_SRC)/build/bin
sd-calib: sd-calib.cpp shielded-field.o shielded-field.h shielded-group-key.h shielded-source-quant.h
	$(CXX) $(CXXFLAGS) -DGGML_MAX_NAME=128 -I$(SD_SRC)/include -I$(SD_SRC)/ggml/include -I$(SD_SRC)/ggml/src \
	  -o $@ sd-calib.cpp shielded-field.o -L$(SD_LIB) -lstable-diffusion -lggml -lggml-base $(LDLIBS) -Wl,-rpath,$(SD_LIB)
