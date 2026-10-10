# vms-steward - Linux build: the service on the stub platform, and the tests.
#
# OpenVMS builds with build_vms.com from the same sources (DECISIONS D3).
# -std=c99 -pedantic is deliberate: VSI C is the target compiler, so C11 must
# not creep in. Do not weaken these flags.

CC      ?= cc
CFLAGS  ?= -std=c99 -pedantic -Wall -Wextra -O2 -g
# glibc hides the socket timeout and inet_addr under strict -std=c99 without this.
CFLAGS  += -D_DEFAULT_SOURCE
LDLIBS  ?= -lcrypto

CORE = src/core/st_buf.c src/core/st_fcgi.c src/core/st_json.c src/core/st_http.c \
       src/core/st_route.c
SVC  = src/svc/st_app.c src/svc/svc_session.c
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

fuzz: $(B)/fuzz_parsers
	$(B)/fuzz_parsers 200000

dev: $(B)/steward
	python3 tools/devserver.py $(B)/steward

clean:
	rm -rf $(B)

.PHONY: all test api-test api-test-asan fuzz dev clean
