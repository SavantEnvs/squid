// Fuzzes Squid's HTTP response-header parsing (HttpReply::parseTerminatedPrefix): status line,
// header block (HttpHeader), Cache-Control, Surrogate-Control, Content-Range, Content-Length.
// This is what parses every reply an origin server or cache_peer sends. Link recipe = tests/testHttpReply.
#include "squid.h"
#include "base/TextException.h"
#include "HttpHdrCc.h"
#include "HttpHeader.h"
#include "HttpReply.h"
#include "mem/forward.h"
#include "MemBuf.h"
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include "MemObject.h"
#include "SquidConfig.h"

// Definitions the tests/testHttpReply link recipe expects from its test program.
class SquidConfig Config;
int64_t MemObject::endOffset() const { return 0; }

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    httpHeaderInitModule();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // parseTerminatedPrefix() requires a 0-terminated buffer (see its callers in http.cc)
    std::vector<char> buf(data, data + size);
    buf.push_back('\0');
    try {
        HttpReply::Pointer rep = new HttpReply;
        if (rep->parseTerminatedPrefix(buf.data(), size)) {
            (void)rep->contentRange();
            (void)rep->bodySize(Http::METHOD_GET);
            int64_t expected = 0;
            (void)rep->expectingBody(Http::METHOD_GET, expected);
            if (rep->cache_control)
                { int32_t v = 0; (void)rep->cache_control->hasMaxAge(&v); }
            (void)rep->header.getInt64(Http::HdrType::CONTENT_LENGTH);
            (void)rep->header.getStr(Http::HdrType::LOCATION);
            MemBuf mb;
            mb.init();
            rep->packHeadersUsingSlowPacker(mb);
            mb.clean();
            HttpReply::Pointer cl(rep->clone());
        }
    } catch (...) {
    }
    return 0;
}
