#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common;

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> casAuth(rxweb::server<T>& server, const json& config_j) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "CAS_AUTH"); },
      [&](const rxweb::task<T>& t) {
        SimpleWeb::CaseInsensitiveMultimap header;
        string serviceProvider = config_j.value("serviceProvider", "");
        string finalDest = getFinalDestUrl<T>(t.request);
cout << finalDest << endl;
        const string uri = fmt::format("{0}/cas/login?service={1}",
          serviceProvider,
          finalDest          
        );
        
        header.emplace("Location", uri);
        
        t.response->write(SimpleWeb::StatusCode::redirection_found, header);
      }
    };

  }

}
