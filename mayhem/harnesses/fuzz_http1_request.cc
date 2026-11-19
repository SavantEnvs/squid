// Fuzzes Squid's HTTP/1 request-line + header-block parser (Http::One::RequestParser),
// the code that reads every client request on an http_port. Link recipe = tests/testHttp1Parser.
#include "squid.h"
#include "base/TextException.h"
#include "http/one/RequestParser.h"
#include "http/RequestMethod.h"
#include "mem/forward.h"
#include "SquidConfig.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    // First byte selects the parser configuration (reset per input: every input sets both).
    Config.onoff.relaxed_header_parser = (data[0] & 0x3) == 0 ? 0 : ((data[0] & 0x3) == 1 ? 1 : -1);
    Config.maxRequestHeaderSize = (data[0] & 0x4) ? 1024 : 64 * 1024;
    try {
        Http1::RequestParser hp(data[0] & 0x8);
        const SBuf input(reinterpret_cast<const char *>(data + 1), size - 1);
        if (data[0] & 0x10) {
            // incremental delivery, as from a socket: feed the buffer in two pieces
            const size_t half = (size - 1) / 2;
            SBuf first(input.substr(0, half));
            (void)hp.parse(first);
            SBuf rest = hp.remaining();
            rest.append(input.substr(half));
            (void)hp.parse(rest);
        } else {
            (void)hp.parse(input);
        }
        (void)hp.method().image();
        (void)hp.requestUri().length();
        (void)hp.messageProtocol();
        (void)hp.mimeHeader().length();
        (void)hp.parseStatusCode;
        if (hp.headerBlockSize())
            (void)hp.getHostHeaderField();
    } catch (...) {
    }
    return 0;
}
