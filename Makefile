# vms-steward - Linux build: the service on the stub platform, and the tests.
#
# OpenVMS builds with build_vms.com from the same sources (DECISIONS D3).
# -std=c99 -pedantic is deliberate: VSI C is the target compiler, so C11 must
# not creep in. Do not weaken these flags.

CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2 -g
# glibc hides the socket timeout and inet_addr under strict -std=c99 without this.
CFLAGS  += -D_DEFAULT_SOURCE
# Includes are by bare name: VSI C does not resolve "../" in #include paths
# (docs/NOTES.md), so the directories are named here and in build_vms.com.
CFLAGS  += -Isrc/core -Isrc/svc -Isrc/plat
LDLIBS  ?= -lcrypto

CORE = src/core/st_buf.c src/core/st_fcgi.c src/core/st_json.c src/core/st_http.c \
       src/core/st_route.c src/core/st_lnm.c src/core/st_proc.c
SVC  = src/svc/st_app.c src/svc/svc_session.c src/svc/svc_users.c src/svc/svc_idents.c src/svc/svc_edit.c src/svc/svc_system.c src/svc/svc_access.c src/svc/svc_logicals.c src/svc/svc_processes.c
STUB = src/plat/stub/st_plat_stub.c src/plat/st_crypto_openssl.c

B = build

all: $(B)/steward $(B)/test_core

$(B):
	mkdir -p $(B)

$(B)/steward: $(CORE) $(SVC) $(STUB) src/main/steward_main.c | $(B)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(B)/test_core: $(CORE) $(SVC) $(STUB) tests/unit/test_core.c | $(B)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(B)/steward-asan: $(CORE) $(SVC) $(STUB) src/main/steward_main.c | $(B)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -o $@ $^ $(LDLIBS)

$(B)/test_core-asan: $(CORE) $(SVC) $(STUB) tests/unit/test_core.c | $(B)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -o $@ $^ $(LDLIBS)

$(B)/fuzz_parsers: $(CORE) tests/unit/fuzz_parsers.c | $(B)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -o $@ $^

test: $(B)/test_core
	$(B)/test_core

api-test: $(B)/steward
	python3 tests/api/test_api.py $(B)/steward

# The API suite against a sanitizer build: catches memory errors the unit tests
# do not reach (a use-after-free in the login audit path was found this way).
api-test-asan: $(B)/steward-asan
	python3 tests/api/test_api.py $(B)/steward-asan

# The unit tests under the sanitizers too: an unterminated header list in a test
# read past its array, harmless by luck on Linux and fatal on OpenVMS (Phase 3).
test-asan: $(B)/test_core-asan
	$(B)/test_core-asan

fuzz: $(B)/fuzz_parsers
	$(B)/fuzz_parsers 200000

# Code security audit (D8, docs/security.md). Runs every check available on this
# machine; CI runs the same target with the extra analyzers installed.
#   - GCC's static analyzer over all sources, warnings as errors
#   - cppcheck and flawfinder when installed
#   - project rules (tools/audit_rules.sh)
#   - the sanitizer API run and the fuzzer
ANALYZE_SRC = $(CORE) $(SVC) $(STUB) src/main/steward_main.c
audit: test-asan api-test-asan fuzz
	@# A real compile per file: under -fsyntax-only the analyzer silently does
	@# nothing (checked with a planted double free, 2026-10-10).
	@for f in $(ANALYZE_SRC); do \
	  $(CC) $(CFLAGS) -fanalyzer -Werror -c $$f -o /dev/null || exit 1; \
	done; echo "audit: gcc -fanalyzer clean"
	@if command -v cppcheck >/dev/null; then \
	  cppcheck --std=c99 --enable=warning,portability --error-exitcode=1 --inline-suppr -q src; \
	else echo "audit: cppcheck not installed, skipped (CI runs it)"; fi
	@if command -v flawfinder >/dev/null; then \
	  flawfinder --minlevel=4 --error-level=4 -Q src; \
	else echo "audit: flawfinder not installed, skipped (CI runs it)"; fi
	tools/audit_rules.sh

ui-test: $(B)/steward
	tests/ui/run.sh

dev: $(B)/steward
	python3 tools/devserver.py $(B)/steward

clean:
	rm -rf $(B)

.PHONY: all test test-asan api-test api-test-asan fuzz audit dev clean
