# Targets:
#   make tool                  build the PIN tool .so
#   make benchmark             compile both benchmark programs
#   make run CMD="..."         run any command natively (baseline timing)
#   make pin CMD="..."         run any command under PIN
#   make clean                 remove build artifacts and logs
#
# CMD aliases:
#   make pin CMD='$(SIMPLE)'
#   make pin CMD='$(FALSE_SHARING)'
#   make pin CMD='$(PBZIP2)'
#   make pin CMD='$(XZ)'

CC     = gcc
CFLAGS = -O0 -g -pthread -Wall -Wextra

THREADS ?= 4

LOG_DIR = logs

PIN_ROOT     ?= $(HOME)/pin-4.2
PIN          = $(PIN_ROOT)/pin
PIN_TOOL_DIR = $(PIN_ROOT)/source/tools/CacheSharingDetector
TOOL         = $(PIN_TOOL_DIR)/obj-intel64/cache_sharing_detector.so

# Comman aliases for common benchmarks and programs to run against
SIMPLE        = ./simple_benchmark
FALSE_SHARING = ./false_sharing_benchmark $(THREADS)
PBZIP2        = "/home/josh/Documents/Repos From Source/pbzip2/pbz2" -p$(THREADS) -k -f TestingData/testfile.bin
XZ            = xz -T$(THREADS) -k -f TestingData/testfile.bin

.PHONY: tool
tool:
	$(MAKE) -C $(PIN_TOOL_DIR) obj-intel64/cache_sharing_detector.so

.PHONY: benchmark
benchmark: simple_benchmark false_sharing_benchmark

simple_benchmark false_sharing_benchmark: %: %.c
	$(CC) $(CFLAGS) -o $@ $<

source_lookup: source_lookup.cpp
	$(CXX) -O2 -o $@ $< $(shell pkg-config --cflags --libs libdw)

.PHONY: run
run: $(LOG_DIR)
ifndef CMD
	$(error CMD is not set. Usage: make run CMD="..." or make run CMD='$$(SIMPLE)')
endif
	time $(CMD) 2>&1 | tee $(LOG_DIR)/native-$$(echo "$(CMD)" | tr ' /' '__' | cut -c1-50).log

.PHONY: pin
pin: $(LOG_DIR)
ifndef CMD
	$(error CMD is not set. Usage: make pin CMD="..." or make pin CMD='$$(SIMPLE)')
endif
	base="$(LOG_DIR)/pin-$$(echo "$(CMD)" | tr ' /' '__' | cut -c1-50)" && \
	$(PIN) -t $(TOOL) -ipdump $${base}-ips.txt -- $(CMD) 2>&1 | tee $${base}.log

.PHONY: lookup
lookup: source_lookup
ifndef CMD
	$(error CMD is not set. Usage: make lookup CMD="...")
endif
	./source_lookup "$(LOG_DIR)/pin-$$(echo "$(CMD)" | tr ' /' '__' | cut -c1-50)-ips.txt"

$(LOG_DIR):
	mkdir -p $(LOG_DIR)

.PHONY: clean
clean:
	rm -f simple_benchmark false_sharing_benchmark pin.log
	rm -rf $(LOG_DIR)
