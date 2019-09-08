#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common;

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> casAuth(rxweb::server<T>& server, const json& config_j, const RS256KeyPair& rs256KeyPair) {
    
    bool isRS256Authenticated(shared_ptr<typename SimpleWeb::ServerBase<A>::Request> request) {
      auto it = std::find_if(request->header.begin(), request->header.end(), [](auto& field) {
        return field.first == "x-access-token";
      });

      if (it != request->header.end()) {
        auto pa = decryptJwt(rs256KeyPair->publicKey, val);
        if (pa.first.size() > 0) {
          return false;
        }

        j = jwtObjectToJson(*(pa.second));

        // Has the token expired?
        bool expired = tokenExpired(j);

        if (expired)
          return false;
        else
          return true;
      }

      return false;
    }

    return {
      [](const rxweb::task<T>& t) { return (t.type == "CAS_AUTH"); },
      [&](const rxweb::task<T>& t) {
        SimpleWeb::CaseInsensitiveMultimap header;
        string serviceProvider = config_j.value("serviceProvider", "");
        string finalDest = getFinalDestUrl<T>(t.request, config_j);

        const string uri = fmt::format("{0}/cas/login?service={1}&renew=true",
          serviceProvider,
          finalDest          
        );
        
        header.emplace("Location", uri);
        
        t.response->write(SimpleWeb::StatusCode::redirection_found, header);
      }
    };

  }

}
