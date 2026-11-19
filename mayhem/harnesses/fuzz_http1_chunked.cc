// Fuzzes Squid's HTTP/1.1 chunked transfer-coding decoder (Http::One::TeChunkedParser),
// used on request bodies from clients and reply bodies from origin servers.
#include "squid.h"
#include "base/TextException.h"
#include "http/one/TeChunkedParser.h"
#include "mem/forward.h"
#include "MemBuf.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    MemBuf out;
    out.init(4096, 64 * 1024);
    try {
        Http1::TeChunkedParser hp;
        hp.setPayloadBuffer(&out);
        SBuf buf(reinterpret_cast<const char *>(data), size);
        for (int i = 0; i < 64; ++i) {
            const bool done = hp.parse(buf);
            if (done)
                break;
            buf = hp.remaining();
            if (hp.needsMoreSpace()) {
                out.reset();   // consumer drained the decoded body
                continue;
            }
            break; // needs more input than we have
        }
    } catch (...) {
    }
    out.clean();
    return 0;
}
