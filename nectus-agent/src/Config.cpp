/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of Config class

#include "stdafx.h"
#include "Config.h"

//------------------------------------------------------------------------
Config::Config(std::ifstream& configStream) :
    Config()
{
    ReadConfigFile(configStream);
}

//------------------------------------------------------------------------
void Config::ReadConfigFile(std::ifstream& configStream)
{
    std::string line;
    while (getline(configStream, line))
	{
		size_t pos = line.find_first_not_of(" \t\r\n");
        if (pos != std::string::npos)
        {
            if (line[pos] == '#' || line[pos] == '\0')
            {
				continue;
            }
        }
		size_t delim_pos = line.find_first_of(" \t=", pos);
        std::string option_name;
        if (delim_pos != std::string::npos)
        {
			option_name = line.substr(pos, delim_pos - pos);
        }
        else
        {
			option_name = line;
        }

        std::transform(option_name.begin(), option_name.end(), option_name.begin(), ::toupper);
		size_t value_pos = line.find_first_not_of(" \t=", delim_pos);
        if (value_pos == std::string::npos) continue;   // No value given - skip this option

        std::string option_value;
        option_value = line.substr(value_pos);
        size_t comment_pos = option_value.find_first_of(" \t#");
        if (comment_pos != std::string::npos)
        {
            option_value = option_value.substr(0, comment_pos);
        }

        if (option_name == "AGENT_IP")
        {
            agentIpAddress = option_value;
        }
        else if (option_name == "AGENT_PORT")
        {
            agentPort = ParseULongValue(option_name, option_value);
        }
        else if (option_name == "SERVER_IP")
        {
            serverIpAddress = option_value;
        }
        else if (option_name == "SSL_CERTIFICATE_DIR")
        {
            sslCertificateDir = option_value;
            RemoveTrailingSlash(sslCertificateDir);
        }
        else if (option_name == "NUM_OF_THREADS")
        {
            numOfThreads = ParseULongValue(option_name, option_value);
        }
        else if (option_name == "LOG_DIR")
        {
            logDir = option_value;
            RemoveTrailingSlash(logDir);
        }
        else if (option_name == "SERVER_PRESHARED_KEY")
        {
            presharedKey = option_value;
        }
        else if (option_name == "USER_INSTEAD_OF_ROOT")
        {
            userInsteadOfRoot = option_value;
        }
        else if (option_name == "LOG_LEVEL")
        {
            if (option_value == "error")
            {
                logLevel = error;
            }
            else if (option_value == "info")
            {
                logLevel = info;
            }
            else if (option_value == "debug")
            {
                logLevel = debug;
            }
            else
            {
                throw std::runtime_error("Wrong value passed for " + option_name + ".");
            }
        }
        else if (option_name == "LOG_FLUSH_PERIOD_SECONDS")
        {
            logFlushPeriodSeconds = ParseULongValue(option_name, option_value);
        }
        else if (option_name == "LOG_FILE_MAX_SIZE_MBYTES")
        {
            logFileMaxSizeMbytes = ParseULongValue(option_name, option_value);
        }
        else if (option_name == "LOG_FILE_MAX_COUNT")
        {
            logFileMaxCount = ParseULongValue(option_name, option_value);
        }
	}	
}

//------------------------------------------------------------------------
unsigned long Config::ParseULongValue(const std::string& name, const std::string& value)
{
    try
    {
        return std::stoul(value);
    }
    catch(const std::invalid_argument&)
    {
        throw std::runtime_error("Wrong value given for numeric config parameter " + name);
    }
}

//------------------------------------------------------------------------
void Config::RemoveTrailingSlash(std::string& str)
{
    if (*(str.end() - 1) == '/')
    {
        str.erase(str.end() - 1);
    }
}

//------------------------------------------------------------------------
void Config::ValidateParams()
{
    boost::system::error_code ec;
    asio::ip::make_address(agentIpAddress, ec);
    if (ec)
    {
        throw std::runtime_error("Wrong AGENT_IP: " + agentIpAddress);
    }
    asio::ip::make_address(serverIpAddress, ec);
    if (ec)
    {
        throw std::runtime_error("Wrong SERVER_ IP: " + serverIpAddress);
    }
    if (numOfThreads < 1 || numOfThreads > 32)
    {
        throw std::runtime_error("Wrong NUM_OF_THREADS");
    }
    if (sslCertificateDir.empty())
    {
        throw std::runtime_error("SSL_CERTIFICATE_DIR is not set");
    }
    if (presharedKey.empty())
    {
        throw std::runtime_error("SERVER_PRESHARED_KEY is not set");
    }
    if (logFlushPeriodSeconds < 1 || logFlushPeriodSeconds > 900)
    {
        throw std::runtime_error("Wrong LOG_FLUSH_PERIOD_SECONDS");
    }
    if (logFileMaxSizeMbytes < 1 || logFileMaxSizeMbytes > 1000)
    {
        throw std::runtime_error("Wrong LOG_FILE_MAX_SIZE_MBYTES");
    }
    if (logFileMaxCount < 1 || logFileMaxCount > 1000)
    {
        throw std::runtime_error("Wrong LOG_FILE_MAX_COUNT");
    }
}

//------------------------------------------------------------------------
std::string Config::DumpAllSettings()
{
    std::stringstream ss;
    ss << "AGENT_IP: " << agentIpAddress << std::endl
       << "AGENT_PORT: " << agentPort << std::endl
       << "SERVER_IP: " << serverIpAddress << std::endl
       << "NUM_OF_THREADS: " << numOfThreads << std::endl
       << "SSL_CERTIFICATE_DIR: " << sslCertificateDir << std::endl
       << "SERVER_PRESHARED_KEY: " << (presharedKey.empty() ? "<NOT SET>" : "*******") << std::endl
       << "USER_INSTEAD_OF_ROOT: " << userInsteadOfRoot << std::endl
       << "LOG_DIR: " << logDir << std::endl
       << "LOG_LEVEL: " << (logLevel == error ? "error" :
                                    (logLevel == debug ? "debug" : "info")) << std::endl
       << "LOG_FLUSH_PERIOD_SECONDS: " << logFlushPeriodSeconds << std::endl
       << "LOG_FILE_MAX_SIZE_MBYTES: " << logFileMaxSizeMbytes << std::endl
       << "LOG_FILE_MAX_COUNT: " << logFileMaxCount << std::endl;
    return ss.str();
}

