/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains definition of CWebsocketConnectionListener class

#include "spdlog/sinks/rotating_file_sink.h"
#include "WebsocketConnectionListener.h"
#include "WebsocketConnectionSession.h"

extern std::shared_ptr<spdlog::logger> logger;

//////////////////////////////////////////////////////////////////////////
CWebsocketConnectionListener::CWebsocketConnectionListener(asio::io_context& ioc, ssl::context& ctx, tcp::endpoint endpoint,
                     const asio::ip::address &allowedPeer)
    : m_sslContext(ctx)
    , m_acceptor(ioc)
    , m_allowedPeer(allowedPeer)
    , m_socket(ioc)
{
    error_code ec;

    // Open the acceptor
    m_acceptor.open(endpoint.protocol(), ec);
    if(ec)
    {
        LogError(ec, "open");
        return;
    }

    // Allow address reuse
    m_acceptor.set_option(asio::socket_base::reuse_address(true));
    if(ec)
    {
        LogError(ec, "set_option");
        return;
    }

    // Bind to the server address
    m_acceptor.bind(endpoint, ec);
    if(ec)
    {
        LogError(ec, "bind");
        return;
    }

    // Start listening for connections
    m_acceptor.listen(asio::socket_base::max_listen_connections, ec);
    if(ec)
    {
        LogError(ec, "listen");
        return;
    }
    m_createdSuccessfully = true;
}

//------------------------------------------------------------------------
// Start accepting incoming connections
void CWebsocketConnectionListener::Run()
{
    // Start accepting a connection
    DoAccept();

}

//------------------------------------------------------------------------
void CWebsocketConnectionListener::DoAccept()
{
    auto self = shared_from_this();
    m_acceptor.async_accept(m_socket, m_connectedPeer,
        [self](error_code ec)
        {
            self->OnAccept(ec);
        });
}

//------------------------------------------------------------------------
void CWebsocketConnectionListener::OnAccept(error_code ec)
{
    if(ec)
    {
        logger->error("Failed to accept connection: {}", ec.message());
    }
    else
    {
        if (m_allowedPeer != ALL_IP_ADDRESSES_ALLOWED
                && m_connectedPeer.address() != m_allowedPeer)
        {
            // Reject connection from peer
            m_socket.cancel();
            m_socket.close();
            logger->info("[{}] Rejected connection since IP is not allowed",
                         m_connectedPeer.address().to_string());
        }
        else
        {
            logger->info("[{}] Accepted new connection", m_connectedPeer.address().to_string());
            // Create the session and run it
            std::make_shared<CWebsocketConnectionSession>(std::move(m_socket), m_sslContext,
                                       m_connectedPeer.address().to_string())->Run();
        }
    }

    // Accept another connection
    DoAccept();
}

//------------------------------------------------------------------------
void CWebsocketConnectionListener::LogError(error_code ec, const std::string& what)
{
    // Don't report on canceled operations
    if(ec == asio::error::operation_aborted) return;

    logger->error("Failed to perform {}: {}", what, ec.message());
}
