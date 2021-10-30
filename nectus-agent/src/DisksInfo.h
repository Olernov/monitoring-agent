/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of CDisksInfo class

#pragma once
#include <mntent.h>
#include "monitoring.pb.h"

//////////////////////////////////////////////////////////////////////////
// Class CDisksInfo is responsible for:
//  - obtaining current machine's file system info (disks discovery)
//  - obtaining disks free and used space info
//  - obtaining disks I/O rates (read/write)
//  - populating RemoteAgentMessage structures with info obtained
class CDisksInfo
{
public:
    // Obtains info about machine's file system and populates HostDescription structure
    void FillFilesystemInfo(RemoteAgentMessage::HostDescription& descr);

    // Obtains info about disks used space and populates MetricResponse structure
    void FillDiskSpaceInfo(RemoteAgentMessage::MetricResponse& metricResponse);

    // Obtains info about current disks I/O rates and populates MetricResponse structure
    void FillDiskIoRate(const std::string &metricCode,
                        RemoteAgentMessage::MetricResponse& metricResponse);

private:
    const char* MOUNT_ENTRIES_TABLE = "/proc/self/mounts";
    const char* DISK_STATS_TABLE = "/proc/diskstats";
    static const int DISK_STATS_SECTOR_SIZE_BYTES = 512; // See https://stackoverflow.com/questions/37248948/how-to-get-disk-read-write-bytes-per-second-from-proc-in-programming-on-linux#38136179

    struct DiskInfo
    {
        std::string fullName;   // Generated name of disk looking like '/dev/sda1 mounted on /'
        std::string mountPoint;
        double totalSizeGbytes;
        double usedSpaceGbytes;
    };

    // Hash map to store disk info. Key is the filesystem name (from /proc/self/mounts)
    // for filtering in IsDiskAccountable function. But for monitoring service and the database
    // key is the full disk name generated in GenerateUniqueDiskName. Multimap is used because
    // filesystem names may contain duplicates.
    std::unordered_multimap<std::string /*filesystem name*/, DiskInfo> m_disksInfo;
    std::chrono::system_clock::time_point m_disksInfoObtainTime;
    std::mutex m_disksInfoMutex;

    struct DiskIoCounterValue
    {
        uintmax_t sectorsRead;
        uintmax_t sectorsWritten;
        uintmax_t sectorsDiscarded;
        uintmax_t readsCompleted;
        uintmax_t writesCompleted;
    };

    using DiskIoCounterValuesMap = std::unordered_map<std::string /*diskName*/, DiskIoCounterValue>;

    struct DiskIoRate
    {
        std::string diskName;
        double readRateMbytesPerSec;
        double writeRateMbytesPerSec;
        double transactionsPerSec;
    };
    std::vector<DiskIoRate> m_diskIoRates;
    std::chrono::system_clock::time_point m_diskIoRateObtainTime;
    std::mutex m_diskIoRateMutex;

    bool ValidateDisksInfoCache(const std::string& nameToLog, std::string errorDescr);

    bool ObtainDisksInfo(std::string& errorDescr);

    // Generates full disk name looking like '/dev/sda1 mounted on /'
    std::string GenerateFullDiskName(const mntent &mnt);

    bool MustBeIgnored(const mntent &mnt);

    bool ObtainDiskIoRates(std::string& errorDescr);

    bool GetDiskCounterValues(DiskIoCounterValuesMap& counterValuesMap,
                                              std::string& errorDescr);

    bool ValidateDiskIoRateCache(const std::string& metricCode,
                                                   std::string& errorDescr);

    bool IsDiskAccountable(const std::string& diskName);
};
