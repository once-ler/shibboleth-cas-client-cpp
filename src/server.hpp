#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"
#include "shibboleth-cas-client-cpp/src/middleware/middlewares.hpp"
#include "shibboleth-cas-client-cpp/src/route/routes.hpp"

using namespace shibboleth::cas::middleware;
using namespace shibboleth::cas::route;

namespace shibboleth::cas::server {

  static string version = "0.1.0";

  json config_j;
  int threads = 4, port = 3000;

  auto start = [] {

    rxweb::server<SimpleWeb::HTTP> server(port, threads);

    server.onNext = finalHandler(server);

    server.routes = {
      auth(server, config_j),
      validate(server, config_j)
    };
    
    server.middlewares = {
      casAuth(server),
      validateTicket(server)
    };
    
    std::thread server_thread([&server]() {
      server.start();
    });

    std::this_thread::sleep_for(std::chrono::seconds(1));

    cout << "Listening on port: " << port << endl;
  };

}
