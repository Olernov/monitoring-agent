/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of CNetworkInfo class

#include "stdafx.h"
#include <iomanip>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include "Common.h"
#include "NetworkInfo.h"

extern std::shared_ptr<spdlog::logger> logger;

//------------------------------------------------------------------------
void CNetworkInfo::FillNetworkInterfaces(RemoteAgentMessage::HostDescription& descr)
{
    NetInterfacesMap netInterfaces;
    struct ifaddrs* interfaceAddrs;
    if (getifaddrs(&interfaceAddrs) != 0)
    {
        logger->error("[FillNetworkAdapters] Call to getifaddrs() failed. Error {}",
                      errno);
        return;

    }
    auto* currentInterface = interfaceAddrs;
    while(currentInterface != nullptr)
    {
        if (currentInterface->ifa_addr)
        {
            switch (currentInterface->ifa_addr->sa_family)
            {
            case AF_INET:
            {
                const auto* sockAddrv4 =
                        reinterpret_cast<sockaddr_in*>(currentInterface->ifa_addr);
                netInterfaces[currentInterface->ifa_name].ipv4AddressNetOrder =
                        sockAddrv4->sin_addr.s_addr;
                break;
            }
            case AF_INET6:
            {
                const auto* sockAddrv6 =
                        reinterpret_cast<sockaddr_in6*>(currentInterface->ifa_addr);

                // These pointer is valid only until freeifaddrs()
                // is called so don't use it outside this function
                netInterfaces[currentInterface->ifa_name].ipv6Address =
                        &(sockAddrv6->sin6_addr.s6_addr);
                break;
            }
            case AF_PACKET:
            {
                const auto *sockAddrll =
                        reinterpret_cast<sockaddr_ll*>(currentInterface->ifa_addr);
                // See comment about ipv6Address, the same applies to macAddress pointer
                netInterfaces[currentInterface->ifa_name].macAddress =
                        reinterpret_cast<const uint8_t*>(&(sockAddrll->sll_addr));
                netInterfaces[currentInterface->ifa_name].macAddressLen =
                        sockAddrll->sll_halen;
            }
            }
        }
        if (currentInterface->ifa_netmask)
        {
            switch (currentInterface->ifa_netmask->sa_family)
            {
            case AF_INET:
            {
                auto* sockNetMaskv4 =
                        reinterpret_cast<sockaddr_in*>(currentInterface->ifa_netmask);
                netInterfaces[currentInterface->ifa_name].ipv4NetMaskNetOrder =
                        sockNetMaskv4->sin_addr.s_addr;
                break;
            }
            case AF_INET6:
            {
                auto* sockNetMaskv6 =
                        reinterpret_cast<sockaddr_in6*>(currentInterface->ifa_netmask);
                // See comment about ipv6Address, the same applies to ipv6NetMask pointer
                netInterfaces[currentInterface->ifa_name].ipv6NetMask =
                        &(sockNetMaskv6->sin6_addr.s6_addr);
                break;
            }
            }
        }
        // Get interface capacity if it was not obtained before
        if (netInterfaces[currentInterface->ifa_name].capacityMbits == 0)
        {
            netInterfaces[currentInterface->ifa_name].capacityMbits
                    = GetInterfaceCapacityMbits(currentInterface->ifa_name);
        }
        currentInterface = currentInterface->ifa_next;
    }
    freeifaddrs(interfaceAddrs);

    if (REMOVE_VIRTUAL_INTERFACES)
    {
        RemoveVirtualNetworkInterfaces(netInterfaces);
    }

    logger->debug("[FillNetworkInterfaces] Network interfaces discovered:");
    for (const auto& netIf : netInterfaces)
    {
        logger->debug("[FillNetworkInterfaces] {}: IPv4: {}, IPv4 netmask: {}, "
                     "IPv6: {}, IPv6 netmask: {} MAC: {}, capacity: {} Mbits",
             netIf.first,
             GetPrintableIPv4(netIf.second.ipv4AddressNetOrder),
             GetPrintableIPv4(netIf.second.ipv4NetMaskNetOrder),
             GetPrintableIPv6(netIf.second.ipv6Address),
             GetPrintableIPv6(netIf.second.ipv6NetMask),
             GetPrintableMac(netIf.second.macAddress, netIf.second.macAddressLen),
             netIf.second.capacityMbits);
        auto intf = descr.add_netinterfaces();
        intf->set_interfacename(netIf.first);
        intf->set_ipv4address(ntohl(netIf.second.ipv4AddressNetOrder));
        intf->set_ipv4netmask(ntohl(netIf.second.ipv4NetMaskNetOrder));
        if (netIf.second.ipv6Address)
        {
            intf->set_ipv6address(netIf.second.ipv6Address, IPV6_ADDRESS_SIZE_BYTES);
        }
        if (netIf.second.ipv6NetMask)
        {
            intf->set_ipv6netmask(netIf.second.ipv6NetMask, IPV6_ADDRESS_SIZE_BYTES);
        }
        if (netIf.second.macAddress)
        {
            intf->set_macaddress(netIf.second.macAddress, netIf.second.macAddressLen);
        }
        intf->set_speedmbits(netIf.second.capacityMbits);
    }
}

//------------------------------------------------------------------------
std::string CNetworkInfo::GetPrintableIPv6(const IPv6Type* ipv6)
{
    if (!ipv6) return "<NULL>";

    char ipPrintable[INET6_ADDRSTRLEN];
    auto* res = inet_ntop(AF_INET6, ipv6, ipPrintable, sizeof(ipPrintable));
    if (res != nullptr)
    {
        return res;
    }
    else
    {
        return std::string("<inet_ntop errno: >") + std::to_string(errno);
    }
}

//------------------------------------------------------------------------
std::string CNetworkInfo::GetPrintableIPv4(uint32_t ipv4)
{
    if (!ipv4) return "<NULL>";

    char ipPrintable[INET_ADDRSTRLEN];
    auto* res = inet_ntop(AF_INET, &ipv4, ipPrintable, sizeof(ipPrintable));
    if (res != nullptr)
    {
        return res;
    }
    else
    {
        return std::string("<inet_ntop errno: >") + std::to_string(errno);
    }
}

//------------------------------------------------------------------------
std::string CNetworkInfo::GetPrintableMac(const uint8_t* macAddress, uint8_t macLen)
{
    if (!macAddress) return "<NULL>";

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t i = 0; i < macLen; ++i)
    {
        ss << std::setw(2) << static_cast<unsigned int>(macAddress[i]);
        if (i < macLen - 1)
        {
            ss << ':';
        }
    }
    return ss.str();
}

//------------------------------------------------------------------------
// Based on https://github.com/lyonel/lshw/tree/master/src/core/network.cc
uint32_t CNetworkInfo::GetInterfaceCapacityMbits(const char* interfaceName)
{
    uint32_t capacityMbits = 0;
    int fd = socket(PF_INET, SOCK_DGRAM, 0); // Necessary to make ioctl calls
    if (fd < 0)
    {
        logger->error("[GetInterfaceCapacityMbits] socket creation failed. Errno={}", errno);
        return capacityMbits;
    }
    ethtool_cmd  ecmd;
    ecmd.cmd = ETHTOOL_GSET;
    ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interfaceName, sizeof(ifr.ifr_name));
    ifr.ifr_data = reinterpret_cast<caddr_t>(&ecmd);
    if (ioctl(fd, SIOCETHTOOL, &ifr) == 0)
    {
        if(ecmd.supported & SUPPORTED_10000baseT_Full)
        {
            capacityMbits = 10000;
        }
        else if(ecmd.supported & SUPPORTED_1000baseT_Half
                || ecmd.supported & SUPPORTED_1000baseT_Full)
        {
            capacityMbits = 1000;
        }
        else if(ecmd.supported & SUPPORTED_100baseT_Half
                || ecmd.supported & SUPPORTED_100baseT_Full)
        {
            capacityMbits = 100;
        }
        else if(ecmd.supported & SUPPORTED_10baseT_Half
                || ecmd.supported & SUPPORTED_10baseT_Full)
        {
            capacityMbits = 10;
        }
    }
    else
    {
        logger->debug("[GetInterfaceCapacityMbits] ioctl call failed for \"{}\". Errno={}",
                      ifr.ifr_name, errno);
    }
    close(fd);
    return capacityMbits;
}

//------------------------------------------------------------------------
template<typename T>
void CNetworkInfo::RemoveVirtualNetworkInterfaces(T& netInterfaces)
{
    // Remove from the interfaces list lo, VPNs, network bridges,
    // IFB devices, bond interfaces, etc and leave physical interfaces only.
    // Physical are all the network interfaces that are listed in /proc/net/dev,
    // but do not exist in /sys/devices/virtual/net.
    // This is a NetData approach (https://github.com/netdata/netdata).
    if (netInterfaces.empty()) return;
    try
    {
        bfs::path virtualNetDir(NETWORK_VIRTUAL_DEVICES);
        bfs::directory_iterator endIterator;
        for(bfs::directory_iterator iter(virtualNetDir); iter != endIterator; iter++)
        {
            auto numErased = netInterfaces.erase(iter->path().stem().string());
            if (numErased > 0)
            {
                logger->debug("[RemoveVirtualNetworkInterfaces] {} removed as virtual",
                              iter->path().stem().string());
            }
        }
    }
    catch(const std::exception& ex)
    {
        // Not a significant error so just log it and don't escalate
        logger->error("[RemoveVirtualNetworkInterfaces] {}", ex.what());
    }
}
//------------------------------------------------------------------------
void CNetworkInfo::FillNetworkThroughput(std::string metricCode, // Passed by value due to async execution
                                        RemoteAgentMessage::MetricResponse& metricResponse)
{
    // We use caching here to obtain both read and write rate at the same time
    // to use for two subsequent metric requests.
    // Also see comments about caching at CDisksInfo::FillFilesystemInfo.
    std::unique_lock<std::mutex> lock(m_networkThroughputMutex);
    std::string errorDescr;
    if(!ValidateNetworkThroughputCache(metricCode, errorDescr))
    {
        logger->error("[FillNetworkThroughput] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }
    for (const auto& nti : m_networkThroughput)
    {
        metricResponse.set_metriccode(metricCode);
        auto metricValue = metricResponse.add_values();
        metricValue->set_devicename(nti.interfaceName);
        metricValue->set_value(metricCode == "net.rx" ?
                                   nti.readRateKbitsPerSec : nti.writeRateKbitsPerSec);
        metricValue->set_maximumvalue(metricCode == "net.rx" ?
                                   nti.readRateKbitsPerSec : nti.writeRateKbitsPerSec);
    }
    metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
}

//------------------------------------------------------------------------
bool CNetworkInfo::ValidateNetworkThroughputCache(const std::string& metricCode,
                                               std::string& errorDescr)
{
    if (std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::system_clock::now() - m_networkThroughputObtainTime).count()
            > CACHED_DATA_VALIDITY_PERIOD_SEC)
    {
        logger->debug("[ValidateNetworkThroughputCache] {}: Cached network throughput info"
                      " is missing or too old, updating it", metricCode);
        m_networkThroughput.clear();
        if (!ObtainNetworkThroughput(errorDescr))
        {
            return false;
        }
        m_networkThroughputObtainTime = std::chrono::system_clock::now();
    }
    else
    {
        logger->debug("[ValidateNetworkThroughputCache] {}: Using cached network throughput info",
                      metricCode);
    }
    return true;
}

//------------------------------------------------------------------------
bool CNetworkInfo::ObtainNetworkThroughput(std::string& errorDescr)
{
    NetCounterValuesMap counterValuesMap1, counterValuesMap2;
    auto firstMeasureTime = std::chrono::high_resolution_clock::now();
    if (!GetNetworkCounterValues(counterValuesMap1, errorDescr))
    {
        return false;
    }

    // Take 500ms pause and make a second measure of counters
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto secondMeasureTime = std::chrono::high_resolution_clock::now();
    if (!GetNetworkCounterValues(counterValuesMap2, errorDescr))
    {
        return false;
    }

    // Don't rely on pause duration and calculate elapsed time
    double elapsedSec = std::chrono::duration_cast<std::chrono::duration<double>>(
                secondMeasureTime - firstMeasureTime).count();

    // Combine counter maps from first and second measures
    for (auto counter1 = counterValuesMap1.begin(); counter1 != counterValuesMap1.end();
         ++counter1)
    {
        auto counter2 = counterValuesMap2.find(counter1->first);
        if (counter2 != counterValuesMap2.end())
        {
            // Check for counter overflow/wrap. Implemented the same way
            // as in systat/iostat.c (write_basic_stat function)
            auto readBytesDiff = counter2->second.first - counter1->second.first;
            if ((counter2->second.first < counter1->second.first)
                    && (counter1->second.first <= 0xffffffff)) {
                readBytesDiff &= 0xffffffff;
            }
            auto writeBytesDiff = counter2->second.second - counter1->second.second;
            if ((counter2->second.second < counter1->second.second)
                    && (counter1->second.second <= 0xffffffff)) {
                writeBytesDiff &= 0xffffffff;
            }
            double readRateKbitsPerSec = readBytesDiff / elapsedSec * 8 / 1000;
            double writeRateKbitsPerSec = writeBytesDiff / elapsedSec * 8 / 1000;

            logger->debug("[ObtainNetworkThroughputInfo] {} read rate: {} kbps, write rate: {} kbps",
                counter1->first, readRateKbitsPerSec, writeRateKbitsPerSec);
            m_networkThroughput.push_back({ counter1->first,
                           readRateKbitsPerSec, writeRateKbitsPerSec });
        }
    }
    return true;
}

//------------------------------------------------------------------------
bool CNetworkInfo::GetNetworkCounterValues(NetCounterValuesMap& counterValuesMap,
                                          std::string& errorDescr)
{
    std::ifstream netDevices(NETWORK_DEVICES_TABLE);
    if (!netDevices.is_open())
    {
        errorDescr = std::string("Unable to open ") + NETWORK_DEVICES_TABLE
                + " to get network counters values";
        return false;
    }
    std::string line;
    // Skip first 2 lines
    std::getline(netDevices, line);
    std::getline(netDevices, line);
    if (netDevices.eof())
    {
        errorDescr = std::string("Number of lines in ") + NETWORK_DEVICES_TABLE
                + "is less than expected";
        return false;
    }
    while(std::getline(netDevices, line))
    {
        std::istringstream ss(line);
        std::string ifName;
        ss >> ifName;
        // extract interfaces names
        size_t pos = ifName.find(':');
        if (pos == std::string::npos)
        {
            // Semicolon is not found, don't raise error but just skip this line
            continue;
        }
        auto adapterId = StripDeviceName(ifName.substr(0, pos));

        const int RECEIVE_BYTES_COUNTER_INDEX_IN_LINE = 0;
        const int TRANSMIT_BYTES_COUNTER_INDEX_IN_LINE = 8;
        std::array<uintmax_t, TRANSMIT_BYTES_COUNTER_INDEX_IN_LINE + 1> counters;
        // Read all counters until Transmit bytes counter
        for(int i = 0; i <= TRANSMIT_BYTES_COUNTER_INDEX_IN_LINE; ++i)
        {
            if (ss.eof())
            {
                errorDescr = std::string("Number of counters in ") + NETWORK_DEVICES_TABLE
                        + " is less than expected";
                return false;
            }
            ss >> counters[i];
            if (ss.fail())
            {
                errorDescr = std::string("Cannot parse next counter in ") + NETWORK_DEVICES_TABLE
                        + "as integer";
                return false;
            }
        }

        counterValuesMap.insert(std::make_pair(adapterId,
            std::make_pair(counters[RECEIVE_BYTES_COUNTER_INDEX_IN_LINE],
                           counters[TRANSMIT_BYTES_COUNTER_INDEX_IN_LINE])));
    }
    if (REMOVE_VIRTUAL_INTERFACES)
    {
        RemoveVirtualNetworkInterfaces(counterValuesMap);
    }
    return true;
}

//------------------------------------------------------------------------
// Based on https://github.com/lyonel/lshw/tree/master/src/core/hw.cc
std::string CNetworkInfo::StripDeviceName(const std::string & s)
{
    std::string result = s;
    size_t pos = result.find('\0');

    if(pos != std::string::npos)
    {
        result = result.substr(0, pos);
    }

    while ((result.length() > 0) && (static_cast<uint8_t>(result[0]) <= ' '))
    {
        result.erase(0, 1);
    }
    while ((result.length() > 0)
           && (static_cast<uint8_t>(result[result.length() - 1]) <= ' '))
    {
        result.erase(result.length() - 1);
    }

    for (size_t i = 0; i < result.length(); i++)
    {
        if (static_cast<uint8_t>(result[i]) < ' ')
        {
          result.erase(i, 1);
          i--;
        }
    }
    result = Utf8_sanitize(result);

    return result;
}

//------------------------------------------------------------------------
// Based on https://github.com/lyonel/lshw/tree/master/src/core/osutils.cc
std::string CNetworkInfo::Utf8_sanitize(const std::string & s, bool autotruncate)
{
    // U+FFFD replacement character
    const std::string REPLACEMENT = "\357\277\275";
    unsigned int i = 0;
    unsigned int remaining = 0;
    std::string result = "";
    std::string emit = "";
    unsigned char c = 0;

    while(i < s.length())
    {
        c = s[i];
        switch(remaining)
        {
        case 3:
        case 2:
        case 1:
            if((0x80<=c) && (c<=0xbf))
            {
              emit += s[i];
              remaining--;
            }
            else // invalid sequence (truncated)
            {
              if(autotruncate) return result;
              emit = REPLACEMENT;
              emit += s[i];
              remaining = 0;
            }
            break;

        case 0:
            result += emit;
            emit = "";

            if(c<=0x7f)
              emit = s[i];
            else
            if((0xc2<=c) && (c<=0xdf)) // start 2-byte sequence
            {
              remaining = 1;
              emit = s[i];
            }
            else
            if((0xe0<=c) && (c<=0xef)) // start 3-byte sequence
            {
              remaining = 2;
              emit = s[i];
            }
            else
            if((0xf0<=c) && (c<=0xf4)) // start 4-byte sequence
            {
              remaining = 3;
              emit = s[i];
            }
            else
            {
              if(autotruncate) return result;
              emit = REPLACEMENT;  // invalid character
            }
            break;
        }
        i++;
    }

    if(remaining == 0)
    result += emit;
    return result;
}
