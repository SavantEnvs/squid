// Fuzzes Squid's URL parser (AnyP::Uri::parse) for the request-target forms a client may send:
// absolute-form, authority-form (CONNECT), origin-form, asterisk-form, urn:. Link recipe = tests/testURL.
#include "squid.h"
#include "anyp/Uri.h"
#include "anyp/UriScheme.h"
#include "base/CharacterSet.h"
#include "base/TextException.h"
#include "http/RequestMethod.h"
#include "mem/forward.h"
#include "sbuf/Stream.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    AnyP::UriScheme::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    static const Http::MethodType methods[] = {Http::METHOD_GET, Http::METHOD_CONNECT,
                                               Http::METHOD_OPTIONS, Http::METHOD_POST};
    const HttpRequestMethod m(methods[data[0] & 3]);
    try {
        AnyP::Uri u;
        const SBuf url(reinterpret_cast<const char *>(data + 1), size - 1);
        if (u.parse(m, url)) {
            (void)u.absolute();
            (void)u.authority(true);
            (void)u.path();
            (void)u.host();
            (void)u.port();
            (void)u.userInfo();
            (void)AnyP::Uri::Decode(u.path());
            (void)AnyP::Uri::Encode(u.path(), CharacterSet::RFC3986_UNRESERVED());
        }
    } catch (...) {
    }
    return 0;
}
