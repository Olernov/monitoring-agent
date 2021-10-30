/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Defines program entry point and start-up procedures

#include "stdafx.h"
#include <pwd.h>
#include <grp.h>
#include <boost/asio/signal_set.hpp>
#include "spdlog/sinks/rotating_file_sink.h"
#include "Common.h"
#include "version.h"
#include "monitoring.pb.h"
#include "Config.h"
#include "WebsocketConnectionListener.h"

// Global objects used throughout the program
std::shared_ptr<spdlog::logger> logger;
Config config;

//const std::string agentVersion = "Nectus monitoring agent version 1.1";

// Path and name of PID file written by daemon and used by systemctl to control the agent
const std::string pidFilename = "/var/run/nectus/nectus-agent.pid";

//------------------------------------------------------------------------
void PrintUsage()
{
    std::cout << "Usage: nectus-agent <config-file> [-D]" << std::endl
              << "   config-file        full path to configuration file" << std::endl
              << "   -D                 debug mode (agent starts not as a daemon but as a usual process) "
              << std::endl;
}

//------------------------------------------------------------------------
void PrintVersion()
{
    std::cout << "Nectus monitoring agent version " << VERSION_NUMBER << std::endl
              << "Copyright 2001-present Virtual Console, LLC <support@nectus5.com>" << std::endl
              << std::endl;
}

//------------------------------------------------------------------------
void LoadCertificate(const std::string& path, asio::ssl::context& ctx)
{
    // Using SSL data from files dh.pem, certificate.pem and key.pem.
    // To generate those files (self-signed certificate) run commands:
    // openssl dhparam -out dh.pem 1024
    // openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out certificate.pem

    ctx.set_password_callback(
        [](std::size_t,
            asio::ssl::context_base::password_purpose)
        {
            return "test";
        });

    ctx.set_options(
        asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::single_dh_use);

    ctx.use_certificate_chain_file(path + "/certificate.pem");
    ctx.use_private_key_file(path + "/key.pem", asio::ssl::context::file_format::pem);
    ctx.use_tmp_dh_file(path + "/dh.pem");
}

//------------------------------------------------------------------------
void IfRootThenDropPrivilegesTo(const std::string& username)
{
    // This code is based on Zabbix daemon_start function (daemon.c)
    if (getuid() != 0)
    {
        // Not running as root, dropping is not needed
        return;
    }
    struct passwd* pwd = getpwnam(username.c_str());
    if (pwd == nullptr)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: user " << username
                  << " does not exist" << std::endl;
        exit(EXIT_FAILURE);
    }
    if (pwd->pw_uid == 0)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: User " << username
                  << "cannot be used to run daemon" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (setgid(pwd->pw_gid) == -1)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: Cannot setgid to " << username
                  << ". Errno=" << errno << std::endl;
        exit(EXIT_FAILURE);
    }
    if (initgroups(username.c_str(), pwd->pw_gid) == -1)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: Cannot initgroups to " << username
                  << ". Errno=" << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    if (setuid(pwd->pw_uid) == -1)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: Cannot setuid to " << username
                  << ". Errno=" << errno << std::endl;
        exit(EXIT_FAILURE);
    }

    if (setegid(pwd->pw_gid) == -1 || seteuid(pwd->pw_uid) == -1)
    {
        std::cerr << "IfRootThenDropPrivilegesTo: Cannot setegid or seteuid to " << username
                  << ". Errno=" << errno << std::endl;
        exit(EXIT_FAILURE);
    }
}

//------------------------------------------------------------------------
void Daemonize()
{
    // Start daemonizing the process.
    // First fork off the parent process
    auto pid = fork();
    if (pid < 0) exit(EXIT_FAILURE);

    // If we got a good PID, then we can exit the parent process
    if (pid > 0) exit(EXIT_SUCCESS);

    // The child process becomes session leader
    if (setsid() < 0) exit(EXIT_FAILURE);

    signal(SIGHUP, SIG_IGN);

    // Fork off for the second time
    pid = fork();

    // An error occurred
    if (pid < 0) exit(EXIT_FAILURE);

    // Success: Let the parent terminate
    if (pid > 0) exit(EXIT_SUCCESS);

    // Change the file mode mask
    umask(0);

    // Change the current working directory
    if (chdir("/") == -1); // to eliminate compiler warning on unused result

    // Close all open file descriptors
    for (int x = sysconf(_SC_OPEN_MAX); x >= 0; x--)
    {
        close (x);
    }
}

//------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    if (argc < 2)
    {
        PrintUsage();
        exit(EXIT_FAILURE);
    }
    if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h") || !strcmp(argv[1], "/?"))
    {
        PrintUsage();
        exit(EXIT_SUCCESS);
    }
    if (!strcmp(argv[1], "--version"))
    {
        PrintVersion();
        exit(EXIT_SUCCESS);
    }
    bool debugMode = false; // If set to true then the process will not daemonize
    if (argc > 2 && !strcmp(argv[2], "-D"))
    {
        debugMode = true;
    }
    const char* confFilename = argv[1]; // config file name is given in the first argument
    std::ifstream confFile(confFilename, std::ifstream::in);
    if (!confFile.is_open()) {
        std::cerr << "Unable to open config file " << confFilename << std::endl;
        exit(EXIT_FAILURE);
    }

    try {
        config.ReadConfigFile(confFile);
        config.ValidateParams();
    }
    catch(const std::exception& ex) {
        std::cerr << "Error when parsing config file " << confFilename << " " << std::endl;
        std::cerr << ex.what() <<std::endl;
        exit(EXIT_FAILURE);
    }

    if (!debugMode)
    {
        IfRootThenDropPrivilegesTo(config.userInsteadOfRoot);
        Daemonize();

        std::ofstream pidFile(pidFilename, std::ofstream::out);
        if (pidFile.is_open()) {
            pidFile << getpid();
        }
    }
    try {
        logger = spdlog::rotating_logger_mt("logger", config.logDir + "/nectus-agent.log",
            config.logFileMaxSizeMbytes * MEGABYTE_SIZE, config.logFileMaxCount);
        spdlog::set_pattern("%m-%d-%Y %H:%M:%S.%e [%l] %v");
        spdlog::flush_every(std::chrono::seconds(config.logFlushPeriodSeconds));

        switch(config.logLevel)
        {
        case Config::LogLevel::info:
            logger->set_level(spdlog::level::info);
            break;
        case Config::LogLevel::debug:
            logger->set_level(spdlog::level::debug);
            break;
        case Config::LogLevel::error:
            logger->set_level(spdlog::level::err);
            break;
        default:
            // Unknown logging level, set to default level "info"
            logger->set_level(spdlog::level::info);
        }

        logger->info("Nectus monitoring agent start. Configuration settings:\n{}",
                     config.DumpAllSettings());

        // The io_context is required for all I/O
        asio::io_context ioContext(config.numOfThreads);

        // The SSL context is required, and holds certificates
        ssl::context ctx(ssl::context::sslv23);
        LoadCertificate(config.sslCertificateDir, ctx);

        auto const listenAddress = asio::ip::make_address(config.agentIpAddress);

        // Accept connection only from one given IP address or from anyone (if set to "0.0.0.0")
        auto const allowedPeerAddress = asio::ip::make_address(config.serverIpAddress);

        // Create and launch a listening port
        auto listener = std::make_shared<CWebsocketConnectionListener>(ioContext, ctx,
            tcp::endpoint(listenAddress, config.agentPort), allowedPeerAddress);
        if (!listener->IsCreatedSuccessfully())
        {
            throw std::runtime_error("Failed to create listener");
        }
        listener->Run();

        // Capture SIGINT and SIGTERM to perform a clean shutdown
        asio::signal_set signals(ioContext, SIGINT, SIGTERM);
        signals.async_wait(
            [&ioContext](error_code const&, int)
            {
                // Stop the io_context. This will cause run()
                // to return immediately, eventually destroying the
                // io_context and any remaining handlers in it.
                ioContext.stop();
            });

        if (debugMode)
        {
            std::cout << "Nectus monitoring agent started." << std::endl;
        }
        ioContext.run();
    }
    catch (const std::exception& ex)
    {
        if (logger) logger->error("{}. Exiting", ex.what());
        if (debugMode)
        {
            std::cerr << ex.what() <<  ". Exiting." <<std::endl;
        }

    }
    if (logger)
    {
        logger->info("Agent stop.");
        logger->flush();
    }
    if (!debugMode) remove(pidFilename.c_str());
}
