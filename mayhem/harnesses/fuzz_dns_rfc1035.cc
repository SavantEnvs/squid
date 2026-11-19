// Fuzzes Squid's DNS reply decoder (rfc1035MessageUnpack): header, name compression, RRs.
// This is what parses every answer from the configured DNS servers. Link recipe = tests/testDns.
#include "squid.h"
#include "dns/rfc1035.h"
#include <cstdint>
#include <cstddef>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    rfc1035_message *msg = nullptr;
    const int n = rfc1035MessageUnpack(reinterpret_cast<const char *>(data), size, &msg);
    if (msg) {
        for (int i = 0; n > 0 && i < n; ++i)
            (void)msg->answer[i].rdlength;
        rfc1035MessageDestroy(&msg);
    }
    return 0;
}
