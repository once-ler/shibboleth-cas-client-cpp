#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common;

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> casAuth(rxweb::server<T>& server, const json& config_j, const RS256KeyPair& rs256KeyPair) {
    
    auto isAlreadyAuthenticatedWithRS256 = [&](shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request, json& j) -> bool {
      auto it = std::find_if(request->header.begin(), request->header.end(), [](auto& field) {
        return field.first == "x-access-token";
      });

      if (it != request->header.end()) {
        return isRS256Authenticated(rs256KeyPair.publicKey, it->second, j);
      }
    };

    return {
      [](const rxweb::task<T>& t) { return (t.type == "CAS_AUTH"); },
      [&](const rxweb::task<T>& t) {
        SimpleWeb::CaseInsensitiveMultimap header;
        string serviceProvider = config_j.value("serviceProvider", "");
        std::pair<string, string> finalDest = getFinalDestUrl<T>(t.request, config_j);

        json j;
        string uri;
        auto alreadyAuthenticated = isAlreadyAuthenticatedWithRS256(t.request, j);

        if (alreadyAuthenticated) {
          uri = finalDest.second;
        } else {
          uri = fmt::format("{0}/cas/login?service={1}&renew=true",
            serviceProvider,
            finalDest.first         
          );
        }
        
        header.emplace("Location", uri);
        
        t.response->write(SimpleWeb::StatusCode::redirection_found, header);
      }
    };

  }

}
