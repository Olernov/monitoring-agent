/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of class CSystemInfo

#pragma once
#include <mntent.h>
#include "monitoring.pb.h"

//------------------------------------------------------------------------
class CSystemInfo
{
public:
    // Obtains info about hostname, OS release, number of CPUs and populates HostDescription
    void FillHostDescription(RemoteAgentMessage::HostDescription& descr);

    // Obtains current CPU utilization and populates MetricResponse
    void FillCpuUtilization(RemoteAgentMessage::MetricResponse& metricResponse);

    // Obtains current RAM usage and populates MetricResponse
    void FillMemoryUsage(RemoteAgentMessage::MetricResponse& metricResponse);

    // Obtains current uptime and populates MetricResponse
    void FillUptime(RemoteAgentMessage::MetricResponse& metricResponse);

    // Obtains running process list according to given name masks and populates MetricResponse
    void FillProcessList(LocalServerMessage::MetricRequest metricRequest,
                         RemoteAgentMessage::MetricResponse& metricResponse);

private:
    const char* OS_RELEASE_FILE = "/etc/os-release";
    const char* CPU_STATS_TABLE = "/proc/stat";
    const char* UPTIME_TABLE = "/proc/uptime";
    const char* PROCESSES_DIR = "/proc";
    const char* MEM_INFO_TABLE = "/proc/meminfo";

    enum CpuStates
    {
        S_USER = 0,
        S_NICE,
        S_SYSTEM,
        S_IDLE,
        S_IOWAIT,       // since Linux 2.5.41
        S_IRQ,          // since Linux 2.6.0
        S_SOFTIRQ,      // since Linux 2.6.0
        S_STEAL,        // since Linux 2.6.11
        S_GUEST,        // since Linux 2.6.24
        S_GUEST_NICE,   // since Linux 2.6.33
        NUM_CPU_STATES
    };

    struct CpuData
    {
        uintmax_t times[NUM_CPU_STATES] = {0};
    };

    bool ReadStatsCpu(CpuData& cpuData, std::string &errorDescr);

    uintmax_t GetActiveTime(const CpuData& d);

    uintmax_t GetIdleTime(const CpuData& d);

};
