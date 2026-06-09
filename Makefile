# Targets:
#   make setup                 first-time setup: symlink tool, build everything, create venv
#   make tool                  build the PIN tool .so
#   make benchmark             compile both benchmark programs
#   make run CMD="..."         run any command natively (baseline timing)
#   make pin CMD="..."         run any command under PIN (overwrites last run)
#   make study CMD="..."       run RUNS times (default 20), each saved with a timestamp
#   make analyze               aggregate logs/*-stats.csv and produce plots/study.png
#   make lookup CMD="..."      resolve IPs from a pin run to source lines via DWARF
#   make clean                 remove build artifacts and logs
#
# CMD aliases:
#   make pin CMD='$(SIMPLE)'
#   make pin CMD='$(FALSE_SHARING)'
#   make pin CMD='$(PBZIP2)'
#   make pin CMD='$(XZ)'

CC     = gcc
CFLAGS = -O0 -g -pthread -Wall -Wextra

THREADS     ?= 4
RUNS        ?= 20
SAMPLE_RATE ?= 1
FRAMES      ?= 1

LOG_DIR = logs

# Auto-detect PIN: honour PIN_ROOT env var, else try ~/pin, else pick any ~/pin-*/
ifeq ($(origin PIN_ROOT), undefined)
    PIN_ROOT := $(shell \
        if [ -d "$(HOME)/pin" ]; then \
            echo "$(HOME)/pin"; \
        else \
            ls -d $(HOME)/pin-*/ 2>/dev/null | sort -V | tail -1 | sed 's|/$$||'; \
        fi)
endif
PIN          = $(PIN_ROOT)/pin
PIN_TOOL_DIR = $(PIN_ROOT)/source/tools/CacheSharingDetector
TOOL         = $(PIN_TOOL_DIR)/obj-intel64/cache_sharing_detector.so

# Comman aliases for common benchmarks and programs to run against
SIMPLE          = ./simple_benchmark
FALSE_SHARING   = ./false_sharing_benchmark $(THREADS)
PBZIP2          = "/home/josh/Documents/Repos From Source/pbzip2/pbz2" -p$(THREADS) -k -f TestingData/testfile.bin
PBZIP2_PADDED   = ./pbz2-padded -p$(THREADS) -k -f TestingData/testfile.bin
XZ              = xz -T$(THREADS) -k -f TestingData/testfile.bin

.PHONY: setup
setup:
	@echo "=== Cache Sharing Detector setup ==="
	@# check PIN
	@if [ ! -f "$(PIN)" ]; then \
		echo ""; \
		echo "ERROR: PIN not found at $(PIN_ROOT)"; \
		echo ""; \
		echo "Download PIN 4.2 from:"; \
		echo "  https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html"; \
		echo ""; \
		echo "Then either:"; \
		echo "  extract to ~/pin-4.2   (default)"; \
		echo "  or set PIN_ROOT=/path/to/pin before running make"; \
		echo ""; \
		exit 1; \
	fi
	@# check libdw
	@if ! pkg-config --exists libdw 2>/dev/null; then \
		echo "ERROR: libdw not found."; \
		echo "Install via your package manager:"; \
		echo "  Arch:   sudo pacman -S elfutils"; \
		echo "  Ubuntu: sudo apt install libdw-dev"; \
		exit 1; \
	fi
	@# create PIN tool directory and symlink source
	mkdir -p $(PIN_TOOL_DIR)
	@if [ ! -f "$(PIN_TOOL_DIR)/cache_sharing_detector.cpp" ]; then \
		ln -s "$$(pwd)/cache_sharing_detector.cpp" "$(PIN_TOOL_DIR)/cache_sharing_detector.cpp"; \
		echo "Linked cache_sharing_detector.cpp into PIN tool directory."; \
	fi
	@# build
	$(MAKE) tool
	$(MAKE) source_lookup
	@# python venv
	python3 -m venv .venv
	.venv/bin/pip install pandas matplotlib numpy --quiet
	@mkdir -p $(LOG_DIR) plots
	@echo ""
	@echo "=== Setup complete ==="
	@echo "Run ./csd.py to start the interactive shell."

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
	$(PIN) -t $(TOOL) -ipdump $${base}-ips.txt -sample_rate $(SAMPLE_RATE) -frames $(FRAMES) -- $(CMD) 2>&1 | tee $${base}.log

.PHONY: study
study: source_lookup $(LOG_DIR)
ifndef CMD
	$(error CMD is not set. Usage: make study CMD='$$(PBZIP2)' [RUNS=20])
endif
	@echo "Starting study: $(RUNS) runs"
	@for i in $$(seq 1 $(RUNS)); do \
		echo "--- Run $$i / $(RUNS) ---"; \
		base="$(LOG_DIR)/pin-$$(echo "$(CMD)" | tr ' /' '__' | cut -c1-50)-$$(date +%s)"; \
		$(PIN) -t $(TOOL) -ipdump "$$base-ips.txt" -- $(CMD) 2>&1 | tee "$$base.log"; \
		./source_lookup "$$base-ips.txt" > "$$base-lookup.txt"; \
	done
	@echo "Study done: $(RUNS) runs saved to $(LOG_DIR)/"

# venv is created once; make only reruns pip if the sentinel is missing
.venv/bin/python3:
	python3 -m venv .venv
	.venv/bin/pip install pandas matplotlib numpy --quiet

.PHONY: analyze
analyze: .venv/bin/python3
	.venv/bin/python3 analyze.py $(STUDY_DIR)

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
