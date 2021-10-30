/// Project : Nectus
/// Component : Monitoring Linux Service
/// Copyright : Virtual  Console, LLC  2001-2019
/// Author : Oleg Smirnov
/// Description: Contains standard headers and namespaces aliasing

#pragma once

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/filesystem.hpp>
#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <fstream>
#include <sstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <queue>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/rotating_file_sink.h"

namespace asio = boost::asio;
namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
namespace bfs = boost::filesystem;
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
using error_code = boost::system::error_code;
using namespace std::placeholders;
