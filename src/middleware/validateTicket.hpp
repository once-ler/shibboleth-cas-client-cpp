#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> validateTicket(rxweb::server<T>& server) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "VALIDATE_TICKET"); },
      [&](const rxweb::task<T>& t) {

      }
    };

  }

}
