/// Project : Nectus 
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019 
/// Author : Oleg Smirnov
/// Description: Contains declaration of CWebsocketSslClient class

#pragma once

using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
namespace websocket = boost::beast::websocket;  // from <boost/beast/websocket.hpp>
namespace bs = boost::system;
namespace plh = std::placeholders;

//////////////////////////////////////////////////////////////////////////
// Class CWebsocketSslClient is an asynchronous Websocket client with SSL encryption.
// Built on top of boost::beast and boost::asio services and implements their 
// asynchronous processing model.
class CWebsocketSslClient
{
public:
    using ByteVector = std::vector<uint8_t>;

    // Callback functions formats.
    // bs::error_code indicates an error (if any). If (!error_code) then the operation was successful
    // const char* contains the name of operation caused the error. 
    using CommonCallbackFunc = std::function<void(bs::error_code, const char*)>;    

    // See comment about bs::error_code above.
    // ByteVector references data received from the connection.
    using OnReadCallbackFunc = std::function<void(bs::error_code, ByteVector&&)>;
    
    // Default constructor is not allowed
    CWebsocketSslClient() = delete;

    // Constructs a CWebsocketSslClient object
    CWebsocketSslClient(boost::asio::io_context& ioContext, ssl::context& sslContext);
  
    // Connects to the given remote host by name or IP address, performs SSL and websocket handshakes
    // and calls back onConnect when finished
    void AsyncConnect(const std::string& hostAddress, int tcpPort,
        CommonCallbackFunc onConnectCallback);
    
    // Closes current connections to the remote host and calls onClose
    void AsyncCloseConnection(CommonCallbackFunc onCloseCallback);

    // Writes binary data to the Websocket and calls back onWrite when finished
    void AsyncWriteBinary(const ByteVector& data, CommonCallbackFunc onWriteCallback);

    // Reads binary data from the Websocket and calls back onRead when finished.
    // If no data is available at the moment the function will wait for the data to arrive
    // from the connection.
    void AsyncReadBinary(OnReadCallbackFunc onReadCallback);

    // Determines if the connection to remote host is established
    bool IsConnectionOpen() const  { return m_wsStream.is_open();  }

private:
    static const int READ_TIMEOUT_SECONDS = 10; // Time-out for reading peer's response

    // Websocket asynchronous callback functions
    void OnResolve(bs::error_code errorCode, tcp::resolver::results_type results,
        CommonCallbackFunc onConnectCallback);
    void OnConnect(bs::error_code errorCode, CommonCallbackFunc onConnectCallback);
    void OnSslHandshake(bs::error_code errorCode, CommonCallbackFunc onConnectCallback);
    void OnRead(bs::error_code errorCode, std::size_t bytesTransferred, 
        OnReadCallbackFunc onReadCallback);
    void OnReadTimeOut(bs::error_code ec, OnReadCallbackFunc onReadCallback);
    
    std::string m_hostAddress;
    int m_tcpPort;
    tcp::resolver m_tcpResolver;
    websocket::stream<ssl::stream<tcp::socket>> m_wsStream;
    boost::beast::flat_buffer m_buffer;
    boost::asio::deadline_timer m_timer;
};