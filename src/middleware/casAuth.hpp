#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> casAuth(rxweb::server<T>& server, const json& config_j) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "CAS_AUTH"); },
      [&](const rxweb::task<T>& t) {
        string serviceProvider = config_j.value("serviceProvider", "");
        string finalDest = config_j.value("finalDest", "");

        const string uri = fmt::format("{0}/cas/login?service={1}",
          serviceProvider,
          finalDest          
        );

        cout << uri << endl; 
      }
    };

  }

}
