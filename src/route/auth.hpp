#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::route {

  template<typename T>
  rxweb::Route<T> auth(rxweb::server<T>& server, const json& config_j) {    
    return {
      "/auth",
      "GET",
      [&](HTTPResponse response, HTTPRequest request) {
        auto sub = server.getSubject();
        auto t = WebTask{ request, response };
        t.type = "CAS_AUTH";
        sub.subscriber().on_next(t);
      }
    };
  }

}
