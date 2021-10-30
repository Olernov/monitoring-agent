/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of CDisksInfo class

#include "stdafx.h"
#include "Common.h"
#include "DisksInfo.h"

extern std::shared_ptr<spdlog::logger> logger;

//------------------------------------------------------------------------
void CDisksInfo::FillFilesystemInfo(RemoteAgentMessage::HostDescription& descr)
{
    // We use caching for data that may be requested more than once during
    // one session. For example, list of disks is requested in HostDescription
    // request and then metric "disk.space" may be polled. It makes sense
    // to store disks free space when describing Filesystem
    // and then use this data for "disk.space" metric because actually free space
    // can be easily obtained when composing FileSystem description.
    std::unique_lock<std::mutex> lock(m_disksInfoMutex);
    std::string errorDescr;
    if(!ValidateDisksInfoCache("FillFilesystemInfo", errorDescr))
    {
        logger->error("[FillFilesystemInfo] {}", errorDescr);
        return;
    }
    for (const auto& disk : m_disksInfo)
    {
        auto responseDisk = descr.add_disks();
        responseDisk->set_diskname(disk.second.fullName);
        responseDisk->set_filesystem(disk.first);
        responseDisk->set_mountpoint(disk.second.mountPoint);
    }
}

//------------------------------------------------------------------------
void CDisksInfo::FillDiskSpaceInfo(RemoteAgentMessage::MetricResponse& metricResponse)
{
    std::unique_lock<std::mutex> lock(m_disksInfoMutex);
    std::string errorDescr;

    // See comment above in FillFilesystemInfo about caching
    if(!ValidateDisksInfoCache("FillDiskSpaceInfo", errorDescr))
    {
        logger->error("[FillDiskSpaceInfo] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }
    for (const auto& disk : m_disksInfo)
    {
        auto metricValue = metricResponse.add_values();
        metricValue->set_devicename(disk.second.fullName);
        metricValue->set_value(disk.second.usedSpaceGbytes);
        metricValue->set_maximumvalue(disk.second.totalSizeGbytes);
    }
    metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
}

//------------------------------------------------------------------------
bool CDisksInfo::ValidateDisksInfoCache(const std::string& nameToLog,
                                               std::string errorDescr)
{
    if (std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::system_clock::now() - m_disksInfoObtainTime).count()
            > CACHED_DATA_VALIDITY_PERIOD_SEC)
    {
        logger->debug("[{}] Cached disks info is missing or too old, updating it", nameToLog);
        m_disksInfo.clear();
        if (!ObtainDisksInfo(errorDescr))
        {
            return false;
        }
        m_disksInfoObtainTime = std::chrono::system_clock::now();
    }
    else
    {
        logger->debug("[{}] Using cached disks info", nameToLog);
    }
    return true;
}

//------------------------------------------------------------------------
bool CDisksInfo::ObtainDisksInfo(std::string& errorDescr)
{
    auto fp = setmntent(MOUNT_ENTRIES_TABLE, "r");
    if (fp == nullptr)
    {
        errorDescr = "setmntent returned NULL";
        return false;
    }

    for(auto mnt = getmntent(fp); mnt; mnt = getmntent(fp))
    {
        auto diskName = GenerateFullDiskName(*mnt);
        boost::system::error_code ec;
        bfs::space_info si = bfs::space(mnt->mnt_dir, ec);

        // Filtering pseudo, duplicate and dummy filesystems is quite complicated
        // (as it's implemented in df utility).
        // Here we use simplified approach: include only filesystems having capacity > 0
        // and not ignored due to other reasons
        if (!ec && si.capacity != 0 && !MustBeIgnored(*mnt))
        {
            auto sizeGbytes = static_cast<double>(si.capacity) / GIGABYTE_SIZE;
            auto usedSpaceGbytes =
                    static_cast<double>(si.capacity - si.free) / GIGABYTE_SIZE;
            logger->debug("[ObtainDisksInfo] {} capacity: {} bytes, used: {} bytes",
                diskName, si.capacity, si.capacity - si.free);
            DiskInfo di = { diskName, mnt->mnt_dir, sizeGbytes, usedSpaceGbytes };
            m_disksInfo.emplace(std::make_pair(std::move(mnt->mnt_fsname), std::move(di)));
        }
        else if (ec)
        {
            logger->debug("[ObtainDisksInfo] {}: {}", diskName, ec.message());
            // Don't finish processing, just skip this disk
        }
    }
    endmntent(fp);
    return true;
}

//------------------------------------------------------------------------
std::string CDisksInfo::GenerateFullDiskName(const mntent& mnt)
{
    return std::string(mnt.mnt_fsname) + " mounted on " + mnt.mnt_dir;
}

//------------------------------------------------------------------------
bool CDisksInfo::MustBeIgnored(const mntent& mnt)
{
    // Ignore pseudo-devices (see details at en.wikipedia.org/wiki/Loop_device):
    const char* IGNORED_DISK_NAME_PREFIX = "/dev/loop";
    return strncmp(mnt.mnt_fsname, IGNORED_DISK_NAME_PREFIX, strlen(IGNORED_DISK_NAME_PREFIX)) == 0;
}

//------------------------------------------------------------------------
void CDisksInfo::FillDiskIoRate(const std::string &metricCode,
                                 RemoteAgentMessage::MetricResponse& metricResponse)
{
    // We'll need actual disks info to perform filtering. So update this info before proceeding
    std::unique_lock<std::mutex> diskInfoLock(m_disksInfoMutex);
    std::string errorDescr;
    if(!ValidateDisksInfoCache("FillDiskIoRate", errorDescr))
    {
        logger->error("[FillDiskIoRate] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }

    std::unique_lock<std::mutex> ioRateLock(m_diskIoRateMutex);

    // See comment above in FillFilesystemInfo about caching
    if(!ValidateDiskIoRateCache(metricCode, errorDescr))
    {
        logger->error("[FillDiskIoRate] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }
    for (const auto& dior : m_diskIoRates)
    {
        metricResponse.set_metriccode(metricCode);
        auto metricValue = metricResponse.add_values();
        metricValue->set_devicename(dior.diskName);
        if (metricCode == "disk.read")
        {
            metricValue->set_value(dior.readRateMbytesPerSec);
            metricValue->set_maximumvalue(dior.readRateMbytesPerSec);
        }
        else if (metricCode == "disk.write")
        {
            metricValue->set_value(dior.writeRateMbytesPerSec);
            metricValue->set_maximumvalue(dior.writeRateMbytesPerSec);
        }
        else if (metricCode == "disk.iops")
        {
            metricValue->set_value(dior.transactionsPerSec);
            metricValue->set_maximumvalue(dior.transactionsPerSec);
        }
    }
    metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
}

//------------------------------------------------------------------------
bool CDisksInfo::ValidateDiskIoRateCache(const std::string& metricCode,
                                               std::string& errorDescr)
{
    if (std::chrono::duration_cast<std::chrono::duration<double>>(
        std::chrono::system_clock::now() - m_diskIoRateObtainTime).count()
            > CACHED_DATA_VALIDITY_PERIOD_SEC)
    {
        logger->debug("[ValidateDiskIoRateCache] {}: Cached disk I/O rate is missing "
                      "or too old, updating it", metricCode);
        m_diskIoRates.clear();
        if (!ObtainDiskIoRates(errorDescr))
        {
            return false;
        }
        m_diskIoRateObtainTime = std::chrono::system_clock::now();
    }
    else
    {
        logger->debug("[ValidateDiskIoRateCache] {}: Using cached disk I/O rate info", metricCode);
    }
    return true;
}

//------------------------------------------------------------------------
bool CDisksInfo::ObtainDiskIoRates(std::string& errorDescr)
{
    DiskIoCounterValuesMap counterValuesMap1, counterValuesMap2;
    auto firstMeasureTime = std::chrono::high_resolution_clock::now();
    if (!GetDiskCounterValues(counterValuesMap1, errorDescr))
    {
        return false;
    }

    // Take 500ms pause and make a second measure of counters
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto secondMeasureTime = std::chrono::high_resolution_clock::now();
    if (!GetDiskCounterValues(counterValuesMap2, errorDescr))
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
            auto readSectorsDiff = counter2->second.sectorsRead - counter1->second.sectorsRead;
            if ((counter2->second.sectorsRead < counter1->second.sectorsRead)
                    && (counter1->second.sectorsRead <= 0xffffffff)) {
                readSectorsDiff &= 0xffffffff;
            }
            auto writtenSectorsDiff =
                    counter2->second.sectorsWritten - counter1->second.sectorsWritten;
            if ((counter2->second.sectorsWritten < counter1->second.sectorsWritten)
                    && (counter1->second.sectorsWritten <= 0xffffffff)) {
                writtenSectorsDiff &= 0xffffffff;
            }
            auto discardedSectorsDiff =
                    counter2->second.sectorsDiscarded - counter1->second.sectorsDiscarded;
            if ((counter2->second.sectorsDiscarded < counter1->second.sectorsDiscarded)
                    && (counter1->second.sectorsDiscarded <= 0xffffffff)) {
                discardedSectorsDiff &= 0xffffffff;
            }
            auto readsCompletedDiff =
                    counter2->second.readsCompleted - counter1->second.readsCompleted;
            if ((counter2->second.readsCompleted < counter1->second.readsCompleted)
                    && (counter1->second.readsCompleted <= 0xffffffff)) {
                readsCompletedDiff &= 0xffffffff;
            }
            auto writesCompletedDiff =
                    counter2->second.writesCompleted - counter1->second.writesCompleted;
            if ((counter2->second.writesCompleted < counter1->second.writesCompleted)
                    && (counter1->second.writesCompleted <= 0xffffffff)) {
                writesCompletedDiff &= 0xffffffff;
            }

            auto readRateMbytesPerSec = static_cast<double>(readSectorsDiff)
                    * DISK_STATS_SECTOR_SIZE_BYTES / MEGABYTE_SIZE / elapsedSec;
            auto writeRateMbytesPerSec =
                    static_cast<double>(writtenSectorsDiff + discardedSectorsDiff)
                    * DISK_STATS_SECTOR_SIZE_BYTES / MEGABYTE_SIZE / elapsedSec;
            auto transactionsPerSec =
                    static_cast<double>(readsCompletedDiff + writesCompletedDiff) / elapsedSec;

            logger->debug("[ObtainDisksIoRate] {} read rate: {} Mbytes/sec,"
                          " write rate: {} Mbytes/sec, transactions: {} iops",
                counter1->first, readRateMbytesPerSec, writeRateMbytesPerSec,
                          transactionsPerSec);
            m_diskIoRates.push_back({ counter1->first,
                readRateMbytesPerSec, writeRateMbytesPerSec, transactionsPerSec});
        }
    }
    return true;
}

//------------------------------------------------------------------------
bool CDisksInfo::GetDiskCounterValues(DiskIoCounterValuesMap& counterValuesMap,
                                          std::string& errorDescr)
{
    std::ifstream diskStats(DISK_STATS_TABLE);
    if (!diskStats.is_open())
    {
        errorDescr = std::string("Unable to open ") + DISK_STATS_TABLE;
        return false;
    }
    std::string line;
    while(std::getline(diskStats, line))
    {
        std::istringstream ss(line);
        unsigned long devMajor, devMinor;
        ss >> devMajor >> devMinor;
        std::string diskName;
        ss >> diskName;
        // Make full disk name from the short one in DISK_STATS_TABLE
        diskName = "/dev/" + diskName;
        if (!IsDiskAccountable(diskName))
        {
            // Skip this line
            logger->debug("[GetDiskCounterValues] Disk {} skipped as not accountable", diskName);
            continue;
        }

        uintmax_t readsCompleted = 0, readsMerged = 0, sectorsRead = 0, millisecSpentReading = 0,
            writesCompleted = 0, writesMerged = 0, sectorsWritten = 0, millisecSpentWriting = 0,
            numOfIOsInProgress = 0, millisecSpentDoingIOs = 0, weightedMillisecDoingIOs = 0,
            discardsCompleted = 0, discardsMerged = 0, sectorsDiscarded = 0,
            millisecSpentDiscarding = 0;

        ss >> readsCompleted >> readsMerged >> sectorsRead >> millisecSpentReading
            >> writesCompleted >> writesMerged >> sectorsWritten >> millisecSpentWriting
            >> numOfIOsInProgress >> millisecSpentDoingIOs >> weightedMillisecDoingIOs;
        if (ss.fail())
        {
            errorDescr = std::string("Cannot parse values in ") + DISK_STATS_TABLE
                + " for " + diskName + " as integer";
            return false;
        }

        // Next fields are available only from kernel 4.18+. If there are no such fields
        // then the values will stay equal to 0
        ss >> discardsCompleted >> discardsMerged >> sectorsDiscarded >> millisecSpentDiscarding;

        DiskIoCounterValue value = { sectorsRead, sectorsWritten, sectorsDiscarded,
                                     readsCompleted, writesCompleted };

        // We need fullName of disk here, so look in the disks info hash map obtained before.
        // Actually there may be more than one entry since it's a multimap but we ignore this case here
        auto iter = m_disksInfo.find(diskName);
        if (iter != m_disksInfo.end())
        {
            counterValuesMap.insert(std::make_pair(iter->second.fullName, value));
        }
    }
    return true;
}

//------------------------------------------------------------------------
bool CDisksInfo::IsDiskAccountable(const std::string& diskName)
{
    return m_disksInfo.find(diskName) != m_disksInfo.end();
}
