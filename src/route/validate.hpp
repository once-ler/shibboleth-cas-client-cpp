#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::route {

  template<typename T>
  rxweb::Route<T> validate(rxweb::server<T>& server, const json& config_j) {    
    return {
      "/validate",
      "GET",
      [&](HTTPResponse response, HTTPRequest request) {
        auto sub = server.getSubject();
        auto t = WebTask{ request, response };
        t.type = "VALIDATE_TICKET";
        sub.subscriber().on_next(t);
      }
    };
  }

}
