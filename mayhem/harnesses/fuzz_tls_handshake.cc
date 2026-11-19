// Fuzzes Squid's TLS/SSL handshake parser (Security::HandshakeParser::parseHello), which reads the
// raw records a client sends on an https_port / ssl_bump peek-or-stare (ClientHello, SSLv2-compat
// hello) and the records an origin server sends back during peek/stare (ServerHello, Certificate,
// ...). src/security/Handshake.cc is built without TLS libraries, so this links the real parser.
//
// Like Squid's own callers, the parser is fed the bytes read so far and then the whole accumulated
// buffer (parseHello() returns false when it needs more data). Both message sources are parsed from
// the same input, each by a fresh parser, so nothing is kept across inputs.
#include "squid.h"
#include "base/TextException.h"
#include "mem/forward.h"
#include "sbuf/SBuf.h"
#include "security/Handshake.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    return 0;
}

static void parse(Security::HandshakeParser::MessageSource source, const SBuf &all)
{
    Security::HandshakeParser p(source);
    try {
        // first read: half of the bytes; second read: everything received so far
        if (!p.parseHello(all.substr(0, all.length() / 2)))
            (void)p.parseHello(all);
    } catch (...) {
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const SBuf all(reinterpret_cast<const char *>(data), size);
    parse(Security::HandshakeParser::fromClient, all);
    parse(Security::HandshakeParser::fromServer, all);
    return 0;
}
