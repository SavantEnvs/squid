#!/usr/bin/env bash
#
# mayhem/build.sh — build Squid's fuzz targets and its unit-test oracle.
#
#  1) bootstrap (autotools) once, in-tree, if ./configure is missing
#  2) sanitized + SanCov build of the whole of Squid out of tree in mayhem/build-fuzz/
#     (gives src/squid for the squid.conf target, and the stubbed convenience objects the
#     upstream cppunit programs link against, which the libFuzzer harnesses reuse)
#  3) one libFuzzer binary + one -standalone reproducer per harness in mayhem/harnesses/
#  4) the upstream cppunit programs test.sh runs, built with NORMAL flags in mayhem/build-test/
#
# Re-runnable: configure runs only when a build dir has no config.status; make is incremental.
# Air-gapped: every dependency is an apt package installed by mayhem/Dockerfile.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
M="$SRC/mayhem"

# Squid's configure + build run test programs and code generators; leaks there are not findings.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0}"

CONF_ARGS=(--disable-shared --disable-optimizations --disable-strict-error-checking
  --disable-auth --disable-external-acl-helpers --disable-url-rewrite-helpers
  --disable-storeid-rewrite-helpers --disable-log-daemon-helpers
  --disable-security-cert-validators --disable-security-cert-generators
  --without-openssl --without-gnutls --disable-snmp --disable-wccp --disable-wccpv2
  --disable-htcp --disable-icmp)

# 1) bootstrap
[ -x "$SRC/configure" ] || ./bootstrap.sh

# 2) sanitized build. UBSan's vptr check is relaxed (-fno-sanitize=vptr): the upstream test link
#    recipes the harnesses reuse replace classes with stubs (tests/stub_*.cc), so their RTTI is
#    absent and every vptr-instrumented object fails to link. All other ASan/UBSan checks halt.
mkdir -p "$M/build-fuzz"
FUZZ_CFLAGS="$SANITIZER_FLAGS -fno-sanitize=vptr -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$M/lsan_off.cc" -o "$M/build-fuzz/lsan_off.o"
if [ ! -f "$M/build-fuzz/config.status" ]; then
  (cd "$M/build-fuzz" && "$SRC/configure" CC="$CC" CXX="$CXX" \
     CFLAGS="$FUZZ_CFLAGS" CXXFLAGS="$FUZZ_CFLAGS" \
     LDFLAGS="$SANITIZER_FLAGS -fno-sanitize=vptr $M/build-fuzz/lsan_off.o" \
     "${CONF_ARGS[@]}")
fi
make -C "$M/build-fuzz" -j"$MAYHEM_JOBS"
# the stub objects the harness link lines need
make -C "$M/build-fuzz/src" -j"$MAYHEM_JOBS" \
  tests/testHttp1Parser tests/testHttpRange tests/testURL tests/testHttpReply tests/testDns

# 3) harnesses
B="$M/build-fuzz/src"
INC=(-DHAVE_CONFIG_H -I"$SRC" -I"$SRC/include" -I"$SRC/lib" -I"$SRC/src" -I"$M/build-fuzz/include" -I"$B")
HFLAGS="-std=c++17 $SANITIZER_FLAGS -fno-sanitize=vptr $DEBUG_FLAGS"
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$M/build-fuzz/standalone_main.o"

HTTP1_OBJS="tests/stub_HelperChildConfig.o MemBuf.o tests/stub_MemObject.o String.o tests/stub_cache_cf.o
 tests/stub_cache_manager.o tests/stub_cbdata.o tests/stub_comm.o tests/stub_debug.o tests/stub_event.o
 tests/stub_libanyp.o tests/stub_libmem.o tests/stub_libsecurity.o mime_header.o tests/stub_stmem.o
 tests/stub_store.o tests/stub_store_stats.o tests/stub_tools.o wordlist.o test_tools.o globals.o
 tests/stub_libtime.o SquidConfig.o http/.libs/libhttp.a parser/.libs/libparser.a anyp/.libs/libanyp.a
 base/.libs/libbase.a ip/.libs/libip.a sbuf/.libs/libsbuf.a ../lib/.libs/libmiscutil.a
 ../compat/.libs/libcompatsquid.a"
RANGE_OBJS="HttpHdrContRange.o HttpHdrRange.o tests/stub_HttpHeader.o HttpHeaderTools.o tests/stub_HttpReply.o
 tests/stub_MemBuf.o StrList.o String.o tests/stub_cbdata.o tests/stub_debug.o tests/stub_libhttp.o
 tests/stub_libmem.o sbuf/.libs/libsbuf.a base/.libs/libbase.a ../compat/.libs/libcompatsquid.a"
DNS_OBJS="dns/.libs/libdns.a ../compat/.libs/libcompatsquid.a"
URI_OBJS="tests/stub_HelperChildConfig.o tests/stub_HttpHeader.o tests/stub_HttpRequest.o
 tests/stub_StatHist.o String.o tests/stub_access_log.o tests/stub_cbdata.o tests/stub_debug.o
 tests/stub_libhttp.o tests/stub_libmem.o anyp/.libs/libanyp.a ./.libs/libsquid.a parser/.libs/libparser.a
 base/.libs/libbase.a ip/.libs/libip.a sbuf/.libs/libsbuf.a ../lib/.libs/libmiscencoding.a
 ../compat/.libs/libcompatsquid.a"
REPLY_OBJS="tests/stub_CachePeer.o ConfigParser.o tests/stub_ETag.o tests/stub_HelperChildConfig.o HttpBody.o
 HttpControlMsg.o HttpHdrCc.o HttpHdrContRange.o HttpHdrRange.o HttpHdrSc.o HttpHdrScTarget.o HttpHeader.o
 HttpHeaderTools.o HttpReply.o tests/stub_HttpRequest.o tests/stub_Instance.o MasterXaction.o MemBuf.o Notes.o
 StatCounters.o tests/stub_StatHist.o StrList.o String.o tests/stub_access_log.o tests/stub_cache_cf.o
 tests/stub_cache_manager.o cbdata.o tests/stub_client_side.o tests/stub_comm.o tests/stub_debug.o
 tests/stub_errorpage.o tests/stub_event.o tests/stub_fatal.o tests/stub_fd.o tests/stub_libanyp.o
 tests/stub_libauth.o tests/stub_libcomm.o tests/stub_liberror.o tests/stub_libformat.o tests/stub_libmem.o
 tests/stub_libmgr.o tests/stub_libsecurity.o tests/stub_libsslsquid.o mime_header.o tests/stub_neighbors.o
 tests/stub_store.o tests/stub_store_stats.o tests/stub_tools.o wordlist.o test_tools.o globals.o
 tests/stub_fde.o hier_code.o tests/stub_libtime.o CommCalls.o http/.libs/libhttp.a parser/.libs/libparser.a
 acl/.libs/libacls.a acl/.libs/libapi.a acl/.libs/libstate.a anyp/.libs/libanyp.a ip/.libs/libip.a
 base/.libs/libbase.a ipc/.libs/libipc.a sbuf/.libs/libsbuf.a ../lib/.libs/libmisccontainers.a
 ../lib/.libs/libmiscencoding.a ../lib/.libs/libmiscutil.a ../compat/.libs/libcompatsquid.a"

FTP_OBJS="$HTTP1_OBJS ftp/.libs/libftp.a parser/.libs/libparser.a ip/.libs/libip.a sbuf/.libs/libsbuf.a
 base/.libs/libbase.a ../lib/.libs/libmiscutil.a ../compat/.libs/libcompatsquid.a"
PROXYP_OBJS="$HTTP1_OBJS StrList.o proxyp/.libs/libproxyp.a parser/.libs/libparser.a ip/.libs/libip.a
 sbuf/.libs/libsbuf.a base/.libs/libbase.a ../lib/.libs/libmiscutil.a ../compat/.libs/libcompatsquid.a"
# the real security/Handshake.o (from libsecurity) replaces stub_libsecurity's HandshakeParser stubs
TLS_OBJS="security/.libs/libsecurity.a ${HTTP1_OBJS/tests\/stub_libsecurity.o/} anyp/.libs/libanyp.a
 parser/.libs/libparser.a base/.libs/libbase.a sbuf/.libs/libsbuf.a ../lib/.libs/libmiscutil.a
 ../compat/.libs/libcompatsquid.a"

link_harness() { # <name> <objs>
  local name="$1" objs="$2" o="$M/build-fuzz/$1.o"
  "$CXX" $HFLAGS -fsanitize=fuzzer-no-link "${INC[@]}" -c "$M/harnesses/$name.cc" -o "$o"
  (cd "$B" && "$CXX" $HFLAGS $LIB_FUZZING_ENGINE "$o" "$M/build-fuzz/lsan_off.o" $objs -ldl -o "$M/$name")
  (cd "$B" && "$CXX" $HFLAGS "$M/build-fuzz/standalone_main.o" "$o" "$M/build-fuzz/lsan_off.o" $objs -ldl \
     -o "$M/$name-standalone")
}
link_harness fuzz_http1_request "$HTTP1_OBJS"
link_harness fuzz_http1_chunked "$HTTP1_OBJS"
link_harness fuzz_http_range "$RANGE_OBJS"
link_harness fuzz_dns_rfc1035 "$DNS_OBJS"
link_harness fuzz_uri "$URI_OBJS"
link_harness fuzz_http_reply "$REPLY_OBJS"
link_harness fuzz_proxy_protocol "$PROXYP_OBJS"
link_harness fuzz_ftp_address "$FTP_OBJS"
link_harness fuzz_tls_handshake "$TLS_OBJS"
cp -f "$B/squid" "$M/squid-fuzz"

# 4) the oracle: upstream's cppunit programs, NORMAL flags, separate tree
mkdir -p "$M/build-test"
if [ ! -f "$M/build-test/config.status" ]; then
  (cd "$M/build-test" && env -u SANITIZER_FLAGS "$SRC/configure" CC="$CC" CXX="$CXX" \
     CFLAGS="-g -O1 $COVERAGE_FLAGS" CXXFLAGS="-g -O1 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS" \
     "${CONF_ARGS[@]}")
fi
make -C "$M/build-test" -j"$MAYHEM_JOBS"
make -C "$M/build-test/src" -j"$MAYHEM_JOBS" $(cat "$M/unit-tests.txt")
