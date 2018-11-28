#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {
  template<typename T>
  rxweb::middleware<T> finalHandler(rxweb::server<T>& server) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "FINAL_RESPONSE"); },
      [](const rxweb::task<T>& t) {
        auto res = t.data->value("response", "");
        *(t.response) << "HTTP/1.1 200 OK\r\nContent-Length: " << res.size() << "\r\n\r\n" << res;
      }
    };
  }

}
