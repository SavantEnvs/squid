// Fuzzes Squid's parsers for addresses an FTP server or client sends: PASV/PORT "h1,h2,h3,h4,p1,p2"
// (Ftp::ParseIpPort) and EPRT "|proto|addr|port|" (Ftp::ParseProtoIpPort), plus textual IP parsing
// (Ip::Address from a string). Link recipe = tests/testIpAddress + ftp/libftp.
#include "squid.h"
#include "ftp/Parsing.h"
#include "ip/Address.h"
#include <cstdint>
#include <cstddef>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return -1;
    std::string s(reinterpret_cast<const char *>(data + 1), size - 1);
    if (s.find('\0') != std::string::npos)
        return -1; // all three take NUL-terminated C strings from the control-channel line
    Ip::Address a;
    char buf[MAX_IPSTRLEN];
    switch (data[0] % 3) {
    case 0:
        if (Ftp::ParseIpPort(s.c_str(), (data[0] & 0x10) ? "10.0.0.1" : nullptr, a))
            (void)a.toUrl(buf, sizeof(buf));
        break;
    case 1:
        if (Ftp::ParseProtoIpPort(s.c_str(), a))
            (void)a.toUrl(buf, sizeof(buf));
        break;
    default:
        if ((a = s.c_str())) {
            (void)a.toStr(buf, sizeof(buf));
            (void)a.isIPv4();
            (void)a.isSiteLocal6();
        }
        break;
    }
    return 0;
}
