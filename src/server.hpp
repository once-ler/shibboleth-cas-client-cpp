#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"
#include "shibboleth-cas-client-cpp/src/middleware/middlewares.hpp"
#include "shibboleth-cas-client-cpp/src/route/routes.hpp"

using namespace shibboleth::cas::middleware;
using namespace shibboleth::cas::route;

namespace shibboleth::cas::server {

  static string version = "0.3.0";
  static int defaultPort = 3000;

  int threads = 4;

  auto start = [](const json& config_j) {
    auto client = RedisClient();
    int port = config_j.value("port", defaultPort);
    RS256KeyPair rs256KeyPair = tryGetRS256Key(config_j); 

    rxweb::server<SimpleWeb::HTTP> server(port, threads);

    server.onNext = finalHandler(server);

    server.routes = {
      auth(server, config_j),
      validate(server, config_j),
      session(server, config_j)
    };
    
    server.middlewares = {
      casAuth(server, config_j, rs256KeyPair),
      validateTicket(server, config_j, rs256KeyPair),
      createSession(server, client),
      getSession(server, client)
    };
    
    std::thread server_thread([&server]() {
      server.start();
    });

    std::this_thread::sleep_for(std::chrono::seconds(1));

    cout << "Listening on port: " << port << endl;

    server_thread.join();
  };

}
