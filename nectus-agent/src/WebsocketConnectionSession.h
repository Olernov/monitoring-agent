/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of CWebsocketConnectionSession class

#pragma once
#include "stdafx.h"
#include "monitoring.pb.h"
#include <future>
#include "Aes256Encryptor.h"
#include "SystemInfo.h"
#include "DisksInfo.h"
#include "NetworkInfo.h"

using AgentMessagePtr = std::shared_ptr<RemoteAgentMessage>;
using ByteArray = std::vector<uint8_t>;

//////////////////////////////////////////////////////////////////////////
// Class CWebsocketConnectionSession provides interaction with a peer connected over Websocket
// to process requests and send back the responses.
// Based on example: https://github.com/vinniefalco/CppCon2018/blob/master/websocket_session.hpp
class CWebsocketConnectionSession : public std::enable_shared_from_this<CWebsocketConnectionSession>
{
public:
    CWebsocketConnectionSession(tcp::socket socket, ssl::context& ctx, std::string&& connectedPeer);

    // Start the asynchronous operation
    void Run();

private:
    // List of asio callback functions
    void OnHandshake(boost::system::error_code ec);
    void OnAccept(boost::system::error_code ec);
    void OnRead(boost::system::error_code ec, size_t bytesTransferred);
    void OnWrite(boost::system::error_code ec, size_t bytesTransferred);

    AgentMessagePtr ProcessIncomingMessage();
    AgentMessagePtr GetMetricValues(LocalServerMessage& request);
    AgentMessagePtr GetHostDescription(LocalServerMessage& request);
    AgentMessagePtr NotAcceptedResponse(uint32_t requestId, const std::string& errDescr);
    void SendOutgoingMessage(AgentMessagePtr response);
    void WriteFirstMessageFromQueue();
    void LogError(error_code ec, const std::string& what);
    RemoteAgentMessage::MetricResponse *AddMetricResponseLocked(RemoteAgentMessage *agentResponse);

    tcp::socket m_socket;
    std::string m_connectedPeer;
    websocket::stream<ssl::stream<tcp::socket&>> m_wsStream;
    boost::beast::flat_buffer m_readBuffer;
    std::queue<std::shared_ptr<ByteArray>> m_writeQueue;
    CAes256Encryptor m_encryptor;
    CSystemInfo m_systemInfo;
    CDisksInfo m_disksInfo;
    CNetworkInfo m_networkInfo;
    std::list<std::future<void>> m_futures; // list of asynchronously executed metric collecting tasks
    std::mutex m_addMetricResponseMutex;
};
