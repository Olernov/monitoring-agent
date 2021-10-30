/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of class CSystemInfo

#include "stdafx.h"
#include "Common.h"
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <boost/filesystem.hpp>
#include <boost/regex.hpp>
#include "spdlog/sinks/rotating_file_sink.h"
#include "SystemInfo.h"

extern std::shared_ptr<spdlog::logger> logger;

//------------------------------------------------------------------------
void CSystemInfo::FillHostDescription(RemoteAgentMessage::HostDescription& descr)
{
    std::array<char, 101> hostname{};    // initialized with zeroes
    gethostname(hostname.data(), hostname.size());
    descr.set_hostname(hostname.data());

    std::ifstream osRelease(OS_RELEASE_FILE);
    std::string line, operatingSystem;
    const std::string PRETTY_NAME("PRETTY_NAME="); // line displaying total CPU info
    while(std::getline(osRelease, line))
    {
        if(!line.compare(0, PRETTY_NAME.size(), PRETTY_NAME))
        {
            // copy substring excluding quotation marks
            operatingSystem.assign(line, PRETTY_NAME.size() + 1, line.size() - PRETTY_NAME.size() - 2);
            break;
        }
    }
    descr.set_operatingsystem(operatingSystem);

    auto numberOfCores = sysconf(_SC_NPROCESSORS_ONLN);
    descr.set_numofprocessors(numberOfCores);
    descr.set_numoflogicalprocessors(numberOfCores);
}

//------------------------------------------------------------------------
void CSystemInfo::FillCpuUtilization(RemoteAgentMessage::MetricResponse& metricResponse)
{
    CpuData cpuData1, cpuData2;
    std::string errorDescr;
    // Take snapshot 1
    if (!ReadStatsCpu(cpuData1, errorDescr))
    {
        logger->error("[FillCpuUtilization] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }

    // 500ms pause
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Take snapshot 2
    if (!ReadStatsCpu(cpuData2, errorDescr))
    {
        logger->error("[FillCpuUtilization] {}", errorDescr);
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(errorDescr);
        return;
    }

    double activeTime = static_cast<double>(GetActiveTime(cpuData2) - GetActiveTime(cpuData1));
    double idleTime = static_cast<double>(GetIdleTime(cpuData2) - GetIdleTime(cpuData1));
    double totalTime = activeTime + idleTime;

    auto metricValue = metricResponse.add_values();
    metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
    metricValue->set_value(activeTime / totalTime * 100);
    metricValue->set_maximumvalue(100);
}

//------------------------------------------------------------------------
bool CSystemInfo::ReadStatsCpu(CpuData& cpuData, std::string& errorDescr)
{
    std::ifstream cpuStats(CPU_STATS_TABLE);
    std::string line;
    const std::string STR_CPU_TOTAL("cpu "); // line displaying total CPU info

    while(std::getline(cpuStats, line))
    {
        if(!line.compare(0, STR_CPU_TOTAL.size(), STR_CPU_TOTAL))
        {
            // Cpu stats line found
            std::istringstream ss(line);

            // Read and skip cpu label
            std::string label;
            ss >> label;

            // Read CPU times
            int timeIndex = 0;
            while(!ss.eof() && timeIndex < NUM_CPU_STATES)
            {
                ss >> cpuData.times[timeIndex];
                if (ss.fail())
                {
                    errorDescr = std::string("Cannot parse next cpu time in ")
                            + CPU_STATS_TABLE + " as integer";
                    return false;
                }
                ++timeIndex;
            }

            if (timeIndex < S_IOWAIT)
            {
                // Minimal set of cpu times is required. Other fields were introduced
                // in later versions of Linux and may be missing in current kernel.
                // See enum CpuStates comments on versions.
                errorDescr = std::string("Number of cpu times in ")
                        + CPU_STATS_TABLE + " is less than expected";
                return false;
            }

            // skip detailed information on every CPU 'cause we use only total
            return true;
        }
    }

    errorDescr = std::string("Line starting from 'cpu ' is not found in ") + CPU_STATS_TABLE;
    return false;
}

//------------------------------------------------------------------------
uintmax_t CSystemInfo::GetIdleTime(const CpuData& d)
{
    return d.times[S_IDLE] + d.times[S_IOWAIT];
}

//------------------------------------------------------------------------
uintmax_t CSystemInfo::GetActiveTime(const CpuData& d)
{
    return d.times[S_USER] +
            d.times[S_NICE] +
            d.times[S_SYSTEM] +
            d.times[S_IRQ] +
            d.times[S_SOFTIRQ] +
            d.times[S_STEAL] +
            d.times[S_GUEST] +
            d.times[S_GUEST_NICE];
}

//------------------------------------------------------------------------
void CSystemInfo::FillMemoryUsage(RemoteAgentMessage::MetricResponse& metricResponse)
{
    std::ifstream memInfo(MEM_INFO_TABLE);
    std::string line;
    const std::string STR_MEM_TOTAL("MemTotal:");
    const std::string STR_MEM_AVAILABLE("MemAvailable:");
    unsigned long long memTotalKBytes = 0, memAvailableKBytes = 0;
    bool memTotalFound = false, memAvailableFound = false;

    while(std::getline(memInfo, line))
    {
        std::istringstream ss(line);
        std::string paramName, paramUnit;
        unsigned long long paramValue = 0;
        ss >> paramName;
        if(paramName == STR_MEM_TOTAL || paramName == STR_MEM_AVAILABLE)
        {
            ss >> paramValue >> paramUnit;
            if (paramUnit.empty() || paramUnit != "kB")
            {
                auto errorDescr = fmt::format("Unexpected format of entry: {}", line);
                logger->error("[FillMemoryUsage] {}", errorDescr);
                metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
                metricResponse.set_errordescription(errorDescr);
                return;
            }
            if(paramName == STR_MEM_TOTAL)
            {
                memTotalKBytes = paramValue;
                memTotalFound = true;
            }
            else if(paramName == STR_MEM_AVAILABLE)
            {
                memAvailableKBytes = paramValue;
                memAvailableFound = true;
            }
            logger->debug("[FillMemoryUsage] {}: {} {}", paramName, paramValue, paramUnit);
        }
        if (memTotalFound && memAvailableFound)
        {
            auto memTotalMBytes = static_cast<double>(memTotalKBytes) / 1024;
            auto memAvailableMBytes = static_cast<double>(memAvailableKBytes) / 1024;
            auto memUsedMBytes = memTotalMBytes - memAvailableMBytes;
            logger->debug("[FillMemoryUsage] Total RAM Mbytes: {}, available RAM Mbytes: {},"
                          " used RAM Mbytes: {}", memTotalMBytes, memAvailableMBytes, memUsedMBytes);

            auto metricValue = metricResponse.add_values();
            metricValue->set_value(memUsedMBytes);
            metricValue->set_maximumvalue(memTotalMBytes);
            metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
            return;
        }
    }
    // if we iterated through all entries in the MEM_INFO_TABLE and exited then something went wrong
    auto errorDescr = fmt::format("One or more of the necessary entries {} or {} were not found in {}.",
         STR_MEM_TOTAL, STR_MEM_AVAILABLE, MEM_INFO_TABLE);
    logger->error("[FillMemoryUsage] {}", errorDescr);
    metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
    metricResponse.set_errordescription(errorDescr);
}

//------------------------------------------------------------------------
void CSystemInfo::FillUptime(RemoteAgentMessage::MetricResponse& metricResponse)
{
    double uptimeSeconds;
    if (std::ifstream(UPTIME_TABLE, std::ios::in) >> uptimeSeconds)
    {
        auto metricValue = metricResponse.add_values();
        metricValue->set_value(uptimeSeconds);
        metricValue->set_maximumvalue(uptimeSeconds);
        metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
    }
    else
    {
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(
                    std::string("Unable to obtain data from ") + UPTIME_TABLE);
    }
}

//------------------------------------------------------------------------
void CSystemInfo::FillProcessList(LocalServerMessage::MetricRequest metricRequest, // Passed by value due to async execution
                                  RemoteAgentMessage::MetricResponse& metricResponse)
{
    try
    {
        bfs::path processesDir(PROCESSES_DIR);
        bfs::directory_iterator endIterator;

        // Enumerate all entries in directory and concatenate them into one string
        std::string runningProcessNames;
        auto metricValue = metricResponse.add_values();
        for(bfs::directory_iterator iter(processesDir); iter != endIterator; iter++)
        {
            // Skip non-numeric entries
            int id = atoi(iter->path().stem().c_str());
            if (id > 0)
            {
                // Read contents of virtual /proc/{pid}/cmdline file
                std::string cmdPath = PROCESSES_DIR + std::string("/")
                        + iter->path().stem().string() + "/cmdline";
                std::ifstream cmdFile(cmdPath);
                std::string cmdLine;
                std::getline(cmdFile, cmdLine);
                if (!cmdLine.empty())
                {
                    // man proc(5): The command-line arguments appear
                    // in this file as a set of strings separated by null bytes
                    // ('\0'), with a further null byte after the last string.
                    // So keep first cmdline item which contains the program path
                    // and cut off the latter.
                    size_t pos = cmdLine.find('\0');
                    if (pos != std::string::npos)
                    {
                        cmdLine = cmdLine.substr(0, pos);
                    }
                    // Keep program name only, removing the path
                    pos = cmdLine.rfind('/');
                    if (pos != std::string::npos)
                    {
                        cmdLine = cmdLine.substr(pos + 1);
                    }
                    if (!runningProcessNames.empty())
                    {
                        runningProcessNames.append(",");
                    }
                    runningProcessNames.append(cmdLine);
                }
            }
        }
        logger->debug("[FillProcessList] [{}] Running processes: {}",
                      metricRequest.metriccode(), runningProcessNames);

        // Apply regular expressions
        for(const auto& regExp : metricRequest.nameregexps())
        {
            // Modify reg exp to use for comma-separated strings.
            // (^|,) means either start of line or a comma
            // and (,|$) means either a comma or the end of line
            auto regExpModified = std::string("(^|,)") + regExp + "(,|$)";
            boost::smatch match;
            if (boost::regex_search(runningProcessNames, match,
                boost::regex(regExpModified, boost::regex_constants::icase)))
            {
                metricValue->add_runningprocessesregexps(regExp);
            }
            else
            {
                metricValue->add_notrunningprocessesregexps(regExp);
            }
        }
        metricResponse.set_resultcode(RemoteAgentMessage::SUCCESS);
    }
    catch(const std::exception& ex)
    {
        logger->error("[FillProcessList] {}", ex.what());
        metricResponse.set_resultcode(RemoteAgentMessage::FAILURE);
        metricResponse.set_errordescription(ex.what());
    }
}
