/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of CWebsocketConnectionSession class

#include "stdafx.h"
#include "Common.h"
#include "Config.h"
#include "WebsocketConnectionSession.h"

extern std::shared_ptr<spdlog::logger> logger;
extern Config config;

namespace pb = google::protobuf;

//------------------------------------------------------------------------
CWebsocketConnectionSession::CWebsocketConnectionSession(tcp::socket socket, ssl::context& ctx, std::string &&connectedPeer)
    : m_socket(std::move(socket))   // Take ownership of the socket
    , m_connectedPeer(std::move(connectedPeer))
    , m_wsStream(m_socket, ctx)
    , m_encryptor(config.presharedKey)
{
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::Run()
{
    // Perform the SSL handshake
    m_wsStream.next_layer().async_handshake(
        ssl::stream_base::server, std::bind(&CWebsocketConnectionSession::OnHandshake, shared_from_this(), _1));
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::OnHandshake(boost::system::error_code ec)
{
    if(ec)
    {
        LogError(ec, "Handshake failed");
        return;
    }

    // Accept the websocket handshake
    m_wsStream.async_accept(std::bind(&CWebsocketConnectionSession::OnAccept, shared_from_this(), _1));
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::OnAccept(error_code ec)
{
    if(ec)
    {
        LogError(ec, "Accept failed");
        return;
    }

    // Read a message
    auto self = shared_from_this();
    m_wsStream.async_read(m_readBuffer,
       [self](error_code ec, std::size_t bytes)
       {
           self->OnRead(ec, bytes);
       });
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::OnRead(boost::system::error_code ec, size_t bytesTransferred)
{
    if(ec)
    {
        LogError(ec, "Read failed");
        return;
    }

    auto response = ProcessIncomingMessage();
    m_readBuffer.consume(m_readBuffer.size());

    if (response)
    {
        // Explicit check of log level to avoid unnecessary call to expensive DebugString()
        if (config.logLevel == Config::LogLevel::debug)
        {
            logger->info("[{}] Response: {}", m_connectedPeer, response->DebugString());
        }
        else
        {
            logger->info("[{}] Response #{} sent", m_connectedPeer, response->requestid());
        }
        SendOutgoingMessage(response);
    }
    else
    {
        logger->info("[{}] No response will be sent", m_connectedPeer);
    }

    auto self = shared_from_this();
    // Wait for a new message
    m_wsStream.async_read(m_readBuffer,
       [self](error_code ec, std::size_t bytes)
       {
           self->OnRead(ec, bytes);
       });
}

//------------------------------------------------------------------------
AgentMessagePtr CWebsocketConnectionSession::ProcessIncomingMessage()
{
    // Put the encrypted message to ByteVector
    ByteVector encryptedMessage;
    encryptedMessage.resize(m_readBuffer.size());
    const auto* bufferStart = boost::asio::buffer_cast<const uint8_t*>(
                boost::beast::buffers_front(m_readBuffer.data()));
    encryptedMessage.assign(bufferStart, bufferStart + m_readBuffer.size());

    // Decrypt the message
    ByteVector decryptedMessage;
    if (!m_encryptor.Decrypt(encryptedMessage, decryptedMessage))
    {
        logger->error("[{}] Request decryption failed", m_connectedPeer);
        return std::shared_ptr<RemoteAgentMessage>();
    }

    // Parse decrypted message to obtain LocalServerMessage structure
    LocalServerMessage request;
    if (!request.ParseFromArray(decryptedMessage.data(), decryptedMessage.size()))
    {
        return NotAcceptedResponse(0, "Request parsing failed");
    }
    if (config.logLevel == Config::LogLevel::debug)
    {
        logger->info("[{}] {}", m_connectedPeer, request.DebugString());
    }
    else
    {
        logger->info("[{}] Request #{} accepted", m_connectedPeer, request.requestid());
    }

    // Process message according to request type
    switch(request.requesttype())
    {
    case GET_METRIC_VALUES:
        return GetMetricValues(request);
    case GET_HOST_DESCRIPTION:
        return GetHostDescription(request);
    default:
        return NotAcceptedResponse(request.requestid(), "Request type not supported");
    }
}

//------------------------------------------------------------------------
std::shared_ptr<RemoteAgentMessage> CWebsocketConnectionSession::NotAcceptedResponse(uint32_t requestId, const std::string& errDescr)
{
    auto response = std::make_shared<RemoteAgentMessage>();
    response->set_resultcode(RemoteAgentMessage::FAILURE);
    response->set_requestid(requestId);
    response->set_errordesription(errDescr);

    return response;
}

//------------------------------------------------------------------------
AgentMessagePtr CWebsocketConnectionSession::GetMetricValues(LocalServerMessage& request)
{
    auto agentResponse = std::make_shared<RemoteAgentMessage>();
    agentResponse->set_requesttype(GET_METRIC_VALUES);
    agentResponse->set_resultcode(RemoteAgentMessage::SUCCESS);
    agentResponse->set_requestid(request.requestid());

    // Process requested metrics asynchronously
    for (const auto& m : request.metricrequests())
    {
        if (m.metriccode() == "cpu")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                    &CSystemInfo::FillCpuUtilization, &m_systemInfo, std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "ram")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                    &CSystemInfo::FillMemoryUsage, &m_systemInfo, std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "uptime")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                    &CSystemInfo::FillUptime, &m_systemInfo, std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "net.rx" || m.metriccode() == "net.tx")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            m_futures.emplace_back(std::async(
                    &CNetworkInfo::FillNetworkThroughput, &m_networkInfo,
                                       m.metriccode(), std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "disk.space")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                &CDisksInfo::FillDiskSpaceInfo, &m_disksInfo, std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "disk.read" || m.metriccode() == "disk.write"
                 || m.metriccode() == "disk.iops")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                &CDisksInfo::FillDiskIoRate, &m_disksInfo, m.metriccode(),
                                       std::ref(*metricResponse)));
        }
        else if (m.metriccode() == "process.required"
                 || m.metriccode() == "process.forbidden")
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            m_futures.emplace_back(std::async(
                &CSystemInfo::FillProcessList, &m_systemInfo, m, std::ref(*metricResponse)));
        }
        else
        {
            auto metricResponse = AddMetricResponseLocked(agentResponse.get());
            metricResponse->set_metriccode(m.metriccode());
            metricResponse->set_resultcode(RemoteAgentMessage::FAILURE);
            metricResponse->set_errordescription("Metric code not supported");
        }
    }
    // Wait for async tasks to finish
    for (auto& f : m_futures)
    {
        f.get();
    }
    return agentResponse;
}

//------------------------------------------------------------------------
RemoteAgentMessage::MetricResponse* CWebsocketConnectionSession::AddMetricResponseLocked(RemoteAgentMessage* agentResponse)
{
    // Protobuf docs say it's not safe to access non-const objects
    // simultaneously from multiple threads, so a mutex is needed
    std::unique_lock<std::mutex> lock(m_addMetricResponseMutex);
    return agentResponse->add_metricresponses();
}


//------------------------------------------------------------------------
AgentMessagePtr CWebsocketConnectionSession::GetHostDescription(LocalServerMessage& request)
{
    auto response = std::make_shared<RemoteAgentMessage>();
    response->set_requesttype(GET_HOST_DESCRIPTION);
    response->set_resultcode(RemoteAgentMessage::SUCCESS);
    response->set_requestid(request.requestid());
    m_systemInfo.FillHostDescription(*response->mutable_description());
    m_disksInfo.FillFilesystemInfo(*response->mutable_description());
    m_networkInfo.FillNetworkInterfaces(*response->mutable_description());
    return response;
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::SendOutgoingMessage(AgentMessagePtr response)
{
    auto sizeBytes = response->ByteSizeLong();
    ByteVector plain(sizeBytes);
    if (!response->SerializeToArray(plain.data(), sizeBytes))
    {
        logger->error("[{}] Host description request SerializeToArray failed",
                      m_connectedPeer);
        return;
    }

    auto encrypted = std::make_shared<ByteVector>();
    if (!m_encryptor.Encrypt(plain, response->requestid(), *encrypted))
    {
        logger->error("[{}] Failed to encrypt host description request: ",
                        m_connectedPeer, m_encryptor.GetErrorDescription());
        return;
    }


    // Always add to queue
    m_writeQueue.push(encrypted);

    // Are we already writing to the socket?
    if(m_writeQueue.size() > 1)
    {
        return;
    }

    // We are not currently writing, so send this immediately
    WriteFirstMessageFromQueue();
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::WriteFirstMessageFromQueue()
{
    m_wsStream.binary(true);
    auto self = shared_from_this();
    m_wsStream.async_write(asio::buffer(*m_writeQueue.front()),
        [self](error_code ec, std::size_t bytes)
        {
            self->OnWrite(ec, bytes);
        });
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::OnWrite(boost::system::error_code ec, size_t bytesTransferred)
{
    if(ec)
    {
        LogError(ec, "Write failed");
        return;
    }

    m_writeQueue.pop();

    if (!m_writeQueue.empty())
    {
        WriteFirstMessageFromQueue();
    }
}

//------------------------------------------------------------------------
void CWebsocketConnectionSession::LogError(error_code ec, const std::string& what)
{
    // Don't report on canceled operations
    if(ec == asio::error::operation_aborted || ec == websocket::error::closed) return;

    logger->error("[{}] {}: {}", m_connectedPeer, what, ec.message());
}


