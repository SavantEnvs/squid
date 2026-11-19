// Fuzzes Squid's PROXY protocol v1 (text) / v2 (binary, TLVs) header parser
// (ProxyProtocol::Parse), which reads the first bytes on a proxy_protocol-enabled http_port.
#include "squid.h"
#include "base/TextException.h"
#include "mem/forward.h"
#include "parser/BinaryTokenizer.h"
#include "proxyp/Elements.h"
#include "proxyp/Header.h"
#include "proxyp/Parser.h"
#include "sbuf/SBuf.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerInitialize(int *, char ***)
{
    Mem::Init();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    try {
        const auto parsed = ProxyProtocol::Parse(SBuf(reinterpret_cast<const char *>(data), size));
        if (parsed.header) {
            (void)parsed.header->toMime();
            (void)parsed.header->getValues(0x01);
            (void)parsed.header->getValues(0x02, ',');
            (void)parsed.header->addressFamily();
            (void)parsed.header->hasForwardedAddresses();
            (void)parsed.header->getElem(0x04, "x", ',');
        }
    } catch (...) {
    }
    return 0;
}
