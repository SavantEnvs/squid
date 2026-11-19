// Fuzzes Squid's Range and Content-Range header-value parsers (HttpHdrRange::ParseCreate,
// httpHdrContRangeParseCreate) plus range canonicalization against a content length.
// Link recipe = tests/testHttpRange. Input: "<header value>\n<decimal content length>" (optional).
#include "squid.h"
#include "HttpHdrContRange.h"
#include "HttpHeaderRange.h"
#include "mem/forward.h"
#include "SquidString.h"
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::string in(reinterpret_cast<const char *>(data), size);
    if (in.find('\0') != std::string::npos)
        return -1; // header field values handed to these parsers are NUL-terminated C strings
    std::string value = in, clenStr;
    const auto nl = in.find('\n');
    if (nl != std::string::npos) {
        value = in.substr(0, nl);
        clenStr = in.substr(nl + 1);
    }
    const int64_t clen = clenStr.empty() ? 1000 : strtoll(clenStr.c_str(), nullptr, 10);

    String spec(value.c_str());
    if (HttpHdrRange *r = HttpHdrRange::ParseCreate(&spec)) {
        HttpHdrRange copy(*r);
        (void)copy.willBeComplex();
        (void)copy.firstOffset();
        // Squid uses the post-canonize accessors only once canonize() accepted the ranges
        // (client_side_reply.cc / clientIfRangeMatch callers), mirror that contract.
        if (clen >= 0 && copy.canonize(clen)) {
            (void)copy.lowestOffset(clen);
            (void)copy.isComplex();
            (void)copy.offsetLimitExceeded(clen);
        }
        delete r;
    }
    if (HttpHdrContRange *cr = httpHdrContRangeParseCreate(value.c_str())) {
        HttpHdrContRange *dup = httpHdrContRangeDup(cr);
        delete dup;
        (void)cr->spec.offset; (void)cr->elength;
        delete cr;
    }
    return 0;
}
