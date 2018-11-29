#pragma once

#include <fstream>
#include "rxweb/src/rxweb.hpp"
#include "rxweb/src/server.hpp"
#include "spdlog/fmt/fmt.h"
#include "shibboleth-cas-client-cpp/src/common/apiCall.hpp"

using json = nlohmann::json;
using WebTask = rxweb::task<SimpleWeb::HTTP>;
using SocketType = SimpleWeb::ServerBase<SimpleWeb::HTTP>;
using HTTPRequest = std::shared_ptr<SocketType::Request>;
using HTTPResponse = std::shared_ptr<SocketType::Response>;
