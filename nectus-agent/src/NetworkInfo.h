/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of CNetworkInfo class

#pragma once
#include "monitoring.pb.h"

//////////////////////////////////////////////////////////////////////////
// Class CNetworkInfo is responsible for:
//  - obtaining current machine's network interfaces list
//  - obtaining network interface I/O rates (read/write)
//  - populating RemoteAgentMessage structures with info obtained
class CNetworkInfo
{
public:
    // Obtains info about network interfaces and populates HostDescription structure
    void FillNetworkInterfaces(RemoteAgentMessage::HostDescription& descr);

    // Obtains info about current network I/O rates and populates MetricResponse structure
    void FillNetworkThroughput(std::string metricCode,
                               RemoteAgentMessage::MetricResponse& metricResponse);

private:
    static const bool REMOVE_VIRTUAL_INTERFACES = false;  // Set this to true to remove lo, VPNs,
        // network bridges, IFB devices, bond interfaces, etc and leave physical interfaces only.
    static const size_t IPV6_ADDRESS_SIZE_BYTES = 16;
    static const size_t MAX_ADDR_V6_STR_LEN = 46;
    const char* NETWORK_DEVICES_TABLE = "/proc/net/dev";
    const char* NETWORK_VIRTUAL_DEVICES = "/sys/devices/virtual/net";

    using IPv6Type = uint8_t[IPV6_ADDRESS_SIZE_BYTES];
    struct NetworkInterfaceInfo
    {
        uint32_t ipv4AddressNetOrder = 0;
        uint32_t ipv4NetMaskNetOrder = 0;

        const IPv6Type *ipv6Address = nullptr;
        const IPv6Type *ipv6NetMask = nullptr;
        const uint8_t *macAddress = nullptr;
        uint8_t macAddressLen = 0;
        uint32_t capacityMbits = 0;
    };

    using NetInterfacesMap = std::unordered_map<std::string /*interfaceName*/, NetworkInterfaceInfo>;

    using NetCounterValuesMap = std::unordered_map<std::string /*interfaceName*/,
        std::pair<uintmax_t /*readBytes*/, uintmax_t /*writeBytes*/>>;

    struct NetworkThroughput
    {
        std::string interfaceName;
        double readRateKbitsPerSec;
        double writeRateKbitsPerSec;
    };
    std::vector<NetworkThroughput> m_networkThroughput;
    std::chrono::system_clock::time_point m_networkThroughputObtainTime;
    std::mutex m_networkThroughputMutex;

    uint32_t GetInterfaceCapacityMbits(const char* interfaceName);

    template<typename T>
    void RemoveVirtualNetworkInterfaces(T& netInterfaces);

    bool ValidateNetworkThroughputCache(const std::string& metricCode,
                                            std::string& errorDescr);
    bool ObtainNetworkThroughput(std::string& errorDescr);
    bool GetNetworkCounterValues(NetCounterValuesMap& perfCounterValuesMap,
                                 std::string& errorDescr);

    std::string StripDeviceName(const std::string & s);
    std::string Utf8_sanitize(const std::string & s, bool autotruncate = true);
    std::string GetPrintableIPv6(const IPv6Type *ipv6);
    std::string GetPrintableIPv4(uint32_t ipv4);
    std::string GetPrintableMac(const uint8_t* macAddress, uint8_t macLen);
};
