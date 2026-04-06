#include <pcap.h>

#include <array>
#include <csignal>
#include <cstdint>
#include <ctime>
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

std::string formatMac(const std::uint8_t* mac) {
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

void printHexDump(const std::uint8_t* data, std::size_t size) {
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

bool applyGooseFilter(pcap_t* handle) {
    const std::vector<std::string> filterCandidates = {
        "(ether proto 0x88b8) or (vlan and ether proto 0x88b8) or (vlan and vlan and ether proto 0x88b8)",
        "ether proto 0x88b8",
    };

    bpf_program filterProgram{};
    for (const auto& filter : filterCandidates) {
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

bool parseEtherType(const std::uint8_t* packet, std::size_t length, std::uint16_t& etherType, std::size_t& payloadOffset) {
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

void printPacket(const pcap_pkthdr& header, const std::uint8_t* packet) {
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
    std::cout << std::flush;
}

}  // namespace

int main(int argc, char* argv[]) {
    const std::string interfaceName = argc > 1 ? argv[1] : "en9";

    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    char errorBuffer[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_open_live(interfaceName.c_str(), BUFSIZ, 1, 1000, errorBuffer);
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
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
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