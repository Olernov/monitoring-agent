/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains declaration of CWebsocketConnectionListener class

#pragma once
#include "stdafx.h"

//////////////////////////////////////////////////////////////////////////
// Class CWebsocketConnectionListener accepts incoming connections and launches client sessions.
// Based on example https://github.com/vinniefalco/CppCon2018/
class CWebsocketConnectionListener : public std::enable_shared_from_this<CWebsocketConnectionListener>
{
public:
    CWebsocketConnectionListener(boost::asio::io_context& ioc, ssl::context& ctx, tcp::endpoint endpoint,
              const asio::ip::address& allowedPeer);

    // Checks if the listener was created and initialized successfully
    bool IsCreatedSuccessfully() const { return m_createdSuccessfully; }

    // Start accepting incoming connections
    void Run();

private:
    const asio::ip::address ALL_IP_ADDRESSES_ALLOWED = asio::ip::make_address("0.0.0.0");

    void DoAccept();
    void OnAccept(error_code ec);
    void LogError(error_code ec, const std::string& what);

    ssl::context& m_sslContext;
    tcp::acceptor m_acceptor;
    asio::ip::address m_allowedPeer;
    tcp::socket m_socket;
    tcp::endpoint m_connectedPeer;
    bool m_createdSuccessfully = false;
};
