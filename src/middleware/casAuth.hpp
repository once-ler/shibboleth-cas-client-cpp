#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common;

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> casAuth(rxweb::server<T>& server, const json& config_j, const RS256KeyPair& rs256KeyPair) {
    auto isAlreadyAuthenticatedWithRS256 = [](shared_ptr<typename SimpleWeb::ServerBase<T>::Request> request, const RS256KeyPair& rs256KeyPair, json& j) -> bool {
      string X_ACCESS_TOKEN = "x-access-token";
      // Check querystring for token.
      auto queries = request->parse_query_string();
      auto it3 = queries.find(X_ACCESS_TOKEN);
      if (it3 != queries.end()) {
        return isRS256Authenticated(rs256KeyPair.publicKey, it3->second, j);
      }

      // Check header for token.
      auto it = request->header.find(X_ACCESS_TOKEN);
      if (it != request->header.end() && rs256KeyPair.publicKey.size() > 0) {
        return isRS256Authenticated(rs256KeyPair.publicKey, it->second, j);
      }

      // Check cookie for token.
      auto cookies = getCookies<T>(request);
      auto it2 = cookies.find(X_ACCESS_TOKEN);
      if (it2 != cookies.end() && rs256KeyPair.publicKey.size() > 0) {
        return isRS256Authenticated(rs256KeyPair.publicKey, it2->second, j);
      }
      
      return false;
    };

    return {
      [](const rxweb::task<T>& t) { return (t.type == "CAS_AUTH"); },
      [&](const rxweb::task<T>& t) {
        SimpleWeb::CaseInsensitiveMultimap header;
        string serviceProvider = config_j.value("serviceProvider", "");
        std::pair<string, string> finalDest = getFinalDestUrl<T>(t.request, config_j);

        json j;
        string uri;
        auto alreadyAuthenticated = isAlreadyAuthenticatedWithRS256(t.request, rs256KeyPair, j);

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
