/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of Config class

#pragma once

//////////////////////////////////////////////////////////////////////////
// Config struct is responsible for reading and parsing the configuration file
// and storing configuration parameters that are used throughout the code
struct Config
{
public:
    Config() = default;
    Config(std::ifstream& cfgStream);

    void ReadConfigFile(std::ifstream& cfgStream);
    void ValidateParams();
    std::string DumpAllSettings();

    // Configuration parameters with default values
    std::string agentIpAddress = "0.0.0.0";
    std::string serverIpAddress = "0.0.0.0";
    unsigned int agentPort = 5400;
    unsigned int numOfThreads = 1;
    std::string presharedKey;
    std::string sslCertificateDir;
    std::string userInsteadOfRoot;

    // Logging parameters
	std::string logDir;

    enum LogLevel
    {
        debug = 0,
        info = 1,
        error = 2
    } logLevel = info;

    unsigned int logFlushPeriodSeconds = 30;    // Flush log data to disk after this period expires
    unsigned int logFileMaxSizeMbytes = 30;     // Maximum size of a single log file.
                                // After reaching this size logging switches to the next file
    unsigned int logFileMaxCount = 30;          // Maximum number of stored log files in rotation.
                                // Older log files are deleted

private:
    unsigned long ParseULongValue(const std::string& name, const std::string& value);
    void RemoveTrailingSlash(std::string& str);
};
