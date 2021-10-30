/// Project : Nectus 
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019 
/// Author : Oleg Smirnov
/// Description: Contains definition of CWebsocketSslClient class

#include "stdafx.h"
#include "WebsocketSslClient.h"

//////////////////////////////////////////////////////////////////////////
CWebsocketSslClient::CWebsocketSslClient(boost::asio::io_context& ioContext, ssl::context& sslContext)
    : m_tcpResolver(ioContext)
    , m_wsStream(ioContext, sslContext)
    , m_timer(ioContext)
{
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::AsyncConnect(const std::string& hostAddress, int tcpPort,
    CommonCallbackFunc onConnectCallback)
{
    m_hostAddress = hostAddress;
    m_tcpPort = tcpPort;
    m_tcpResolver.async_resolve(hostAddress, std::to_string(tcpPort),
        std::bind(&CWebsocketSslClient::OnResolve, this, plh::_1, plh::_2, onConnectCallback));
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::OnResolve(bs::error_code errorCode, tcp::resolver::results_type results,
    CommonCallbackFunc onConnectCallback)
{
    // Make the connection on the IP address we get from a lookup
    boost::asio::async_connect(m_wsStream.next_layer().next_layer(),
        results.begin(), results.end(),
        std::bind(&CWebsocketSslClient::OnConnect, this, plh::_1, onConnectCallback));
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::OnConnect(bs::error_code errorCode, CommonCallbackFunc onConnectCallback)
{
    if (errorCode)
    {
        onConnectCallback(errorCode, "Connect");
        return;
    }

    // Perform the SSL handshake
    m_wsStream.next_layer().async_handshake(ssl::stream_base::client,
        std::bind(&CWebsocketSslClient::OnSslHandshake, this, plh::_1, onConnectCallback));
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::OnSslHandshake(bs::error_code errorCode, 
    CommonCallbackFunc onConnectCallback)
{
    if (errorCode)
    {
        onConnectCallback(errorCode, "SSL handshake");
        return;
    }

    // Perform the websocket handshake
    auto callbackFn = onConnectCallback;
    m_wsStream.async_handshake(m_hostAddress, "/",
        [callbackFn] (const bs::error_code& errorCode)
        {
            callbackFn(errorCode, errorCode ? "Websocket handshake" : "");
        }
    );
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::AsyncWriteBinary(const ByteVector& data, 
    CommonCallbackFunc onWriteCallback)
{
    m_wsStream.binary(true);
    auto callbackFn = onWriteCallback;
    m_wsStream.async_write(boost::asio::buffer(data), 
        [callbackFn](const bs::error_code& errorCode, std::size_t bytesTransferred)
        {
            callbackFn(errorCode, errorCode ? "Write" : "");
        }
    );
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::AsyncReadBinary(OnReadCallbackFunc onReadCallback)
{
    // Set timer to process read time-out when no response is received
    m_timer.expires_from_now(boost::posix_time::seconds(READ_TIMEOUT_SECONDS));
    m_timer.async_wait(std::bind(&CWebsocketSslClient::OnReadTimeOut, 
        this, plh::_1, onReadCallback));

    m_wsStream.async_read(m_buffer, std::bind(&CWebsocketSslClient::OnRead, this,
        plh::_1, plh::_2, onReadCallback));
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::OnReadTimeOut(bs::error_code errorCode, OnReadCallbackFunc onReadCallback)
{
    if (errorCode)
    {
        if (errorCode == boost::asio::error::operation_aborted)
        {
            // timer wait operation was aborted
            return;
        }
        onReadCallback(errorCode, ByteVector());
    }

    // Closing the socket cancels all outstanding operations. They
    // will complete with boost::asio::error::operation_aborted
    bs::error_code ec;
    m_wsStream.next_layer().next_layer().shutdown(tcp::socket::shutdown_both, ec);
    m_wsStream.close(websocket::close_code::normal, ec);
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::OnRead(bs::error_code errorCode, std::size_t bytesTransferred,
    OnReadCallbackFunc onReadCallback)
{
    ByteVector data;
    if (!errorCode)
    {
        data.resize(m_buffer.size());
        const auto* bufferStart = boost::asio::buffer_cast<const uint8_t*>(
            boost::beast::buffers_front(m_buffer.data()));
        data.assign(bufferStart, bufferStart + m_buffer.size());
        m_buffer.consume(bytesTransferred);
    }
    // Cancel the time-out timer since we obtained peer's response
    m_timer.cancel();
    onReadCallback(errorCode, std::move(data));
}

//////////////////////////////////////////////////////////////////////////
void CWebsocketSslClient::AsyncCloseConnection(CommonCallbackFunc onCloseCallback)
{
    auto callbackFn = onCloseCallback;
    m_wsStream.async_close(websocket::close_code::normal,
        [callbackFn](const bs::error_code& errorCode)
        {
            callbackFn(errorCode, errorCode ? "Closing connection" : "");
        }
    );
}
