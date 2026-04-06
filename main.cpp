/*
MIT License

Copyright (c) 2026 Pavel Konovalov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <pcap.h>
#include <array>
#include <algorithm>
#include <csignal>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {
    constexpr std::uint16_t kEtherTypeVlan = 0x8100;
    constexpr std::uint16_t kEtherTypeQinQ = 0x88A8;
    constexpr std::uint16_t kEtherTypeGoose = 0x88B8;

    volatile std::sig_atomic_t g_shouldStop = 0;

    std::string formatMac(const std::uint8_t *mac) {
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0) {
                out << ':';
            }
            out << std::setw(2) << static_cast<unsigned>(mac[i]);
        }
        return out.str();
    }

    void printHexDump(const std::uint8_t *data, std::size_t size) {
        constexpr std::size_t kBytesPerLine = 16;

        for (std::size_t offset = 0; offset < size; offset += kBytesPerLine) {
            std::cout << "  " << std::setw(4) << std::setfill('0') << std::hex << offset << "  ";

            for (std::size_t i = 0; i < kBytesPerLine; ++i) {
                const std::size_t index = offset + i;
                if (index < size) {
                    std::cout << std::setw(2) << static_cast<unsigned>(data[index]) << ' ';
                } else {
                    std::cout << "   ";
                }
            }

            std::cout << " |";
            for (std::size_t i = 0; i < kBytesPerLine; ++i) {
                const std::size_t index = offset + i;
                if (index >= size) {
                    break;
                }
                const auto byte = static_cast<unsigned char>(data[index]);
                // Print only plain ASCII to keep console output stable across locales/encodings.
                if (byte >= 0x20 && byte <= 0x7e) {
                    std::cout << static_cast<char>(byte);
                } else {
                    std::cout << '.';
                }
            }
            std::cout << "|\n";
        }
        std::cout << std::dec << std::setfill(' ');
    }

    void handleSignal(int) {
        g_shouldStop = 1;
    }

    bool applyGooseFilter(pcap_t *handle) {
        const std::vector<std::string> filterCandidates = {
            "(ether proto 0x88b8) or (vlan and ether proto 0x88b8) or (vlan and vlan and ether proto 0x88b8)",
            "ether proto 0x88b8",
        };

        bpf_program filterProgram{};
        for (const auto &filter: filterCandidates) {
            if (pcap_compile(handle, &filterProgram, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) != -1) {
                if (pcap_setfilter(handle, &filterProgram) == -1) {
                    std::cerr << "Failed to set filter: " << pcap_geterr(handle) << '\n';
                    pcap_freecode(&filterProgram);
                    return false;
                }
                pcap_freecode(&filterProgram);
                return true;
            }
        }

        std::cerr << "Failed to compile filter: " << pcap_geterr(handle) << '\n';
        return false;
    }

    bool parseEtherType(const std::uint8_t *packet, std::size_t length, std::uint16_t &etherType, std::size_t &payloadOffset) {
        if (length < 14) {
            return false;
        }

        payloadOffset = 14;
        std::size_t etOffset = 12;
        etherType = (static_cast<std::uint16_t>(packet[etOffset]) << 8) | packet[etOffset + 1];

        // Some GOOSE frames are VLAN-tagged. Walk one or two VLAN headers.
        int vlanDepth = 0;
        while ((etherType == kEtherTypeVlan || etherType == kEtherTypeQinQ) && vlanDepth < 2) {
            if (length < payloadOffset + 4) {
                return false;
            }
            etOffset += 4;
            payloadOffset += 4;
            etherType = (static_cast<std::uint16_t>(packet[etOffset]) << 8) | packet[etOffset + 1];
            ++vlanDepth;
        }

        return true;
    }

    struct GooseHeader {
        std::uint16_t appId = 0;
        std::uint16_t declaredLength = 0;
        std::uint16_t reserved1 = 0;
        std::uint16_t reserved2 = 0;
        const std::uint8_t *pdu = nullptr;
        std::size_t pduLength = 0;
        bool isTruncated = false;
    };

    bool parseGooseHeader(const std::uint8_t *payload, std::size_t length, GooseHeader &header) {
        if (length < 8) {
            return false;
        }

        header.appId = (static_cast<std::uint16_t>(payload[0]) << 8) | payload[1];
        header.declaredLength = (static_cast<std::uint16_t>(payload[2]) << 8) | payload[3];
        header.reserved1 = (static_cast<std::uint16_t>(payload[4]) << 8) | payload[5];
        header.reserved2 = (static_cast<std::uint16_t>(payload[6]) << 8) | payload[7];
        header.pdu = payload + 8;

        const std::size_t availablePdu = length - 8;
        if (header.declaredLength < 8) {
            header.pduLength = availablePdu;
            header.isTruncated = true;
            return true;
        }

        const std::size_t declaredPdu = header.declaredLength - 8;
        header.isTruncated = header.declaredLength > length;
        header.pduLength = std::min(availablePdu, declaredPdu);
        return true;
    }

    bool readBerTag(const std::uint8_t *data, std::size_t size, std::size_t &offset, std::uint32_t &tag) {
        if (offset >= size) {
            return false;
        }

        tag = data[offset++];
        if ((tag & 0x1F) != 0x1F) {
            return true;
        }

        // Handle high-tag-number form without allocating.
        for (int i = 0; i < 4; ++i) {
            if (offset >= size) {
                return false;
            }
            const std::uint8_t b = data[offset++];
            tag = (tag << 8) | b;
            if ((b & 0x80U) == 0) {
                return true;
            }
        }

        return false;
    }

    bool readBerLength(const std::uint8_t *data, std::size_t size, std::size_t &offset, std::size_t &valueLength) {
        if (offset >= size) {
            return false;
        }

        const std::uint8_t first = data[offset++];
        if ((first & 0x80U) == 0) {
            valueLength = first;
            return true;
        }

        const std::size_t count = first & 0x7FU;
        if (count == 0 || count > sizeof(std::size_t) || offset + count > size) {
            return false;
        }

        valueLength = 0;
        for (std::size_t i = 0; i < count; ++i) {
            valueLength = (valueLength << 8) | data[offset++];
        }
        return valueLength <= (size - offset);
    }

    bool readBerTlv(const std::uint8_t *data,
                    std::size_t size,
                    std::size_t &offset,
                    std::uint32_t &tag,
                    const std::uint8_t *&value,
                    std::size_t &valueLength) {
        std::size_t localOffset = offset;
        if (!readBerTag(data, size, localOffset, tag)) {
            return false;
        }
        if (!readBerLength(data, size, localOffset, valueLength)) {
            return false;
        }
        if (localOffset + valueLength > size) {
            return false;
        }

        value = data + localOffset;
        offset = localOffset + valueLength;
        return true;
    }

    bool decodeUnsigned(const std::uint8_t *data, std::size_t size, std::uint64_t &value) {
        if (size == 0 || size > sizeof(std::uint64_t)) {
            return false;
        }

        value = 0;
        for (std::size_t i = 0; i < size; ++i) {
            value = (value << 8) | data[i];
        }
        return true;
    }

    bool decodeSigned(const std::uint8_t *data, std::size_t size, std::int64_t &value) {
        if (size == 0 || size > sizeof(std::int64_t)) {
            return false;
        }

        value = (data[0] & 0x80U) != 0 ? -1 : 0;
        for (std::size_t i = 0; i < size; ++i) {
            value = (value << 8) | data[i];
        }
        return true;
    }

    std::string formatBitString(const std::uint8_t *data, std::size_t size) {
        if (size == 0) {
            return "invalid-length";
        }

        const std::uint8_t unusedBits = data[0];
        if (unusedBits > 7) {
            return "invalid-unused-bits";
        }

        std::ostringstream out;
        out << "unusedBits=" << static_cast<unsigned>(unusedBits);
        if (size > 1) {
            out << ", dataHex=";
            out << std::hex << std::setfill('0');
            for (std::size_t i = 1; i < size; ++i) {
                if (i > 1) {
                    out << ' ';
                }
                out << std::setw(2) << static_cast<unsigned>(data[i]);
            }
            out << std::dec << std::setfill(' ');
        }
        return out.str();
    }

    bool decodeMmsFloat32(const std::uint8_t *data, std::size_t size, float &value) {
        // MMS floating-point is encoded as: exponent width byte + IEEE-754 bytes.
        if (size != 5 || data[0] != 8) {
            return false;
        }

        const std::uint32_t bits = (static_cast<std::uint32_t>(data[1]) << 24) |
                                   (static_cast<std::uint32_t>(data[2]) << 16) |
                                   (static_cast<std::uint32_t>(data[3]) << 8) |
                                   static_cast<std::uint32_t>(data[4]);
        std::memcpy(&value, &bits, sizeof(value));
        return true;
    }

    std::string decodeText(const std::uint8_t *data, std::size_t size) {
        std::string out;
        out.reserve(size);
        for (std::size_t i = 0; i < size; ++i) {
            const unsigned char c = data[i];
            if (c >= 0x20 && c <= 0x7e) {
                out.push_back(static_cast<char>(c));
            } else {
                out.push_back('.');
            }
        }
        return out;
    }

    std::string formatBytes(const std::uint8_t *data, std::size_t size) {
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (std::size_t i = 0; i < size; ++i) {
            if (i > 0) {
                out << ' ';
            }
            out << std::setw(2) << static_cast<unsigned>(data[i]);
        }
        return out.str();
    }

    std::string formatGooseTimestamp(const std::uint8_t *data, std::size_t size) {
        if (size != 8) {
            return "invalid-length";
        }

        const std::uint32_t seconds = (static_cast<std::uint32_t>(data[0]) << 24) |
                                      (static_cast<std::uint32_t>(data[1]) << 16) |
                                      (static_cast<std::uint32_t>(data[2]) << 8) |
                                      static_cast<std::uint32_t>(data[3]);
        const std::uint32_t fraction = (static_cast<std::uint32_t>(data[4]) << 16) |
                                       (static_cast<std::uint32_t>(data[5]) << 8) |
                                       static_cast<std::uint32_t>(data[6]);
        const std::uint32_t quality = data[7];

        const std::uint64_t nanos = (static_cast<std::uint64_t>(fraction) * 1000000000ULL) >> 24U;
        const auto epochSeconds = static_cast<std::time_t>(seconds);
        std::tm localTime{};
        localtime_r(&epochSeconds, &localTime);

        std::array<char, 64> timeBuffer{};
        std::strftime(timeBuffer.data(), timeBuffer.size(), "%F %T", &localTime);

        std::ostringstream out;
        out << timeBuffer.data() << '.' << std::setw(9) << std::setfill('0') << nanos << std::setfill(' ')
                << " q=0x" << std::hex << std::setw(2) << std::setfill('0') << quality << std::dec << std::setfill(' ');
        return out.str();
    }

    void printAllDataSummary(const std::uint8_t *data, std::size_t size) {
        std::size_t offset = 0;
        std::size_t index = 0;
        std::cout << "  allData entries:\n";
        while (offset < size) {
            std::uint32_t tag = 0;
            const std::uint8_t *value = nullptr;
            std::size_t valueLength = 0;
            if (!readBerTlv(data, size, offset, tag, value, valueLength)) {
                std::cout << "    [" << index << "] parse error at offset " << offset << '\n';
                return;
            }

            std::cout << "    [" << index << "] tag=0x" << std::hex << tag << std::dec << ", len=" << valueLength;
            switch (tag) {
                case 0x83: {
                    std::cout << ", type=BOOLEAN";
                    if (valueLength == 1) {
                        std::cout << ", value=" << (value[0] == 0 ? "false" : "true");
                    } else {
                        std::cout << ", value=<invalid-length>";
                    }
                    break;
                }
                case 0x84:
                    std::cout << ", type=BIT-STRING, value=" << formatBitString(value, valueLength);
                    break;
                case 0x85: {
                    std::cout << ", type=INTEGER";
                    std::int64_t signedValue = 0;
                    if (decodeSigned(value, valueLength, signedValue)) {
                        std::cout << ", value=" << signedValue;
                    } else {
                        std::cout << ", value=<invalid>";
                    }
                    break;
                }
                case 0x86: {
                    std::cout << ", type=UNSIGNED";
                    std::uint64_t unsignedValue = 0;
                    if (decodeUnsigned(value, valueLength, unsignedValue)) {
                        std::cout << ", value=" << unsignedValue;
                    } else {
                        std::cout << ", value=<invalid>";
                    }
                    break;
                }
                case 0x87: {
                    std::cout << ", type=FLOAT32";
                    float floatValue = 0.0F;
                    if (decodeMmsFloat32(value, valueLength, floatValue)) {
                        std::cout << ", value=" << floatValue;
                    } else {
                        std::cout << ", value=<invalid-format>";
                    }
                    break;
                }
                case 0x89:
                    std::cout << ", type=OCTET-STRING, valueHex=" << formatBytes(value, valueLength);
                    break;
                case 0x8A:
                    std::cout << ", type=VISIBLE-STRING, value=\"" << decodeText(value, valueLength) << "\"";
                    break;
                case 0x91:
                    std::cout << ", type=TIMESTAMP, value=" << formatGooseTimestamp(value, valueLength);
                    break;
                default:
                    if (valueLength > 0 && valueLength <= 32) {
                        std::cout << ", valueHex=" << formatBytes(value, valueLength);
                    }
                    break;
            }
            std::cout << '\n';
            ++index;
        }
    }

    void printGooseDecoded(const std::uint8_t *payload, std::size_t payloadLength) {
        GooseHeader header;
        if (!parseGooseHeader(payload, payloadLength, header)) {
            std::cout << "GOOSE decode: payload too short for GSE header\n";
            return;
        }

        std::cout << "GOOSE decode:\n";
        std::cout << "  APPID: 0x" << std::hex << std::setw(4) << std::setfill('0') << header.appId
                << std::dec << std::setfill(' ') << '\n';
        std::cout << "  Declared length: " << header.declaredLength << " bytes\n";
        std::cout << "  Reserved1: 0x" << std::hex << std::setw(4) << std::setfill('0') << header.reserved1
                << ", Reserved2: 0x" << std::setw(4) << header.reserved2 << std::dec << std::setfill(' ') << '\n';
        if (header.isTruncated) {
            std::cout << "  Warning: frame is shorter than declared GOOSE length\n";
        }

        std::size_t offset = 0;
        std::uint32_t pduTag = 0;
        const std::uint8_t *pduValue = nullptr;
        std::size_t pduValueLength = 0;
        if (!readBerTlv(header.pdu, header.pduLength, offset, pduTag, pduValue, pduValueLength)) {
            std::cout << "  PDU parse error: invalid BER container\n";
            return;
        }
        if (pduTag != 0x61U) {
            std::cout << "  PDU parse warning: expected tag 0x61, got 0x" << std::hex << pduTag << std::dec << '\n';
        }

        std::size_t pduOffset = 0;
        while (pduOffset < pduValueLength) {
            std::uint32_t tag = 0;
            const std::uint8_t *value = nullptr;
            std::size_t valueLength = 0;
            if (!readBerTlv(pduValue, pduValueLength, pduOffset, tag, value, valueLength)) {
                std::cout << "  Field parse error at PDU offset " << pduOffset << '\n';
                return;
            }

            switch (tag) {
                case 0x80:
                    std::cout << "  gocbRef: " << decodeText(value, valueLength) << '\n';
                    break;
                case 0x81: {
                    std::uint64_t ttl = 0;
                    if (decodeUnsigned(value, valueLength, ttl)) {
                        std::cout << "  timeAllowedToLive: " << ttl << " ms\n";
                    } else {
                        std::cout << "  timeAllowedToLive: <invalid>\n";
                    }
                    break;
                }
                case 0x82:
                    std::cout << "  datSet: " << decodeText(value, valueLength) << '\n';
                    break;
                case 0x83:
                    std::cout << "  goID: " << decodeText(value, valueLength) << '\n';
                    break;
                case 0x84:
                    std::cout << "  t: " << formatGooseTimestamp(value, valueLength) << '\n';
                    break;
                case 0x85: {
                    std::uint64_t stNum = 0;
                    if (decodeUnsigned(value, valueLength, stNum)) {
                        std::cout << "  stNum: " << stNum << '\n';
                    } else {
                        std::cout << "  stNum: <invalid>\n";
                    }
                    break;
                }
                case 0x86: {
                    std::uint64_t sqNum = 0;
                    if (decodeUnsigned(value, valueLength, sqNum)) {
                        std::cout << "  sqNum: " << sqNum << '\n';
                    } else {
                        std::cout << "  sqNum: <invalid>\n";
                    }
                    break;
                }
                case 0x87:
                    std::cout << "  test: " << ((valueLength > 0 && value[0] != 0) ? "true" : "false") << '\n';
                    break;
                case 0x88: {
                    std::uint64_t confRev = 0;
                    if (decodeUnsigned(value, valueLength, confRev)) {
                        std::cout << "  confRev: " << confRev << '\n';
                    } else {
                        std::cout << "  confRev: <invalid>\n";
                    }
                    break;
                }
                case 0x89:
                    std::cout << "  ndsCom: " << ((valueLength > 0 && value[0] != 0) ? "true" : "false") << '\n';
                    break;
                case 0x8A: {
                    std::uint64_t entries = 0;
                    if (decodeUnsigned(value, valueLength, entries)) {
                        std::cout << "  numDatSetEntries: " << entries << '\n';
                    } else {
                        std::cout << "  numDatSetEntries: <invalid>\n";
                    }
                    break;
                }
                case 0xAB:
                    printAllDataSummary(value, valueLength);
                    break;
                default:
                    std::cout << "  field 0x" << std::hex << tag << std::dec << ": len=" << valueLength;
                    if (valueLength > 0 && valueLength <= 32) {
                        std::cout << ", valueHex=" << formatBytes(value, valueLength);
                    }
                    std::cout << '\n';
                    break;
            }
        }
    }

    void printPacket(const pcap_pkthdr &header, const std::uint8_t *packet) {
        std::uint16_t etherType = 0;
        std::size_t payloadOffset = 0;
        if (!parseEtherType(packet, header.caplen, etherType, payloadOffset)) {
            return;
        }

        if (etherType != kEtherTypeGoose) {
            return;
        }

        std::array<char, 64> timeBuffer{};
        const std::time_t seconds = header.ts.tv_sec;
        std::tm localTime{};
        localtime_r(&seconds, &localTime);
        std::strftime(timeBuffer.data(), timeBuffer.size(), "%F %T", &localTime);

        std::cout << "\n=== GOOSE frame ===\n";
        std::cout << "Time: " << timeBuffer.data() << '.' << std::setw(6) << std::setfill('0') << header.ts.tv_usec
                << std::setfill(' ') << "\n";
        std::cout << "Captured length: " << header.caplen << " bytes, original length: " << header.len << " bytes\n";
        std::cout << "Dst MAC: " << formatMac(packet) << "\n";
        std::cout << "Src MAC: " << formatMac(packet + 6) << "\n";
        std::cout << "EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0') << etherType
                << std::dec << std::setfill(' ') << " (GOOSE)\n";
        std::cout << "Payload offset: " << payloadOffset << " bytes\n";
        std::cout << "Hex dump:\n";
        printHexDump(packet, header.caplen);
        if (header.caplen > payloadOffset) {
            std::cout << "Decoded payload:\n";
            printGooseDecoded(packet + payloadOffset, header.caplen - payloadOffset);
        }
        std::cout << std::flush;
    }
} // namespace

int main(int argc, char *argv[]) {
    const std::string interfaceName = argc > 1 ? argv[1] : "en9";

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);
    if (handle == nullptr) {
        std::cerr << "Failed to open interface '" << interfaceName << "': " << errorBuffer << '\n';
        return 1;
    }

    if (!applyGooseFilter(handle)) {
        pcap_close(handle);
        return 1;
    }

    std::cout << "Listening for IEC 61850 GOOSE packets on interface '" << interfaceName << "'.\n";
    std::cout << "Press Ctrl+C to stop.\n";

    while (g_shouldStop == 0) {
        pcap_pkthdr *header = nullptr;
        const u_char *packet = nullptr;
        const int result = pcap_next_ex(handle, &header, &packet);

        if (result == 1 && header != nullptr && packet != nullptr) {
            printPacket(*header, packet);
            continue;
        }

        if (result == 0) {
            continue;
        }

        if (result == -2) {
            std::cout << "Capture finished.\n";
            break;
        }

        std::cerr << "Capture error: " << pcap_geterr(handle) << '\n';
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    std::cout << "Stopped.\n";
    return 0;
}
