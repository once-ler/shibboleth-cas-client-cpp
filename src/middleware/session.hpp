#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {
  template<typename T>
  rxweb::middleware<T> createSession(rxweb::server<T>& server, store::storage::redis::Client& client) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "CREATE_SESSION"); },
      [](const rxweb::task<T>& t) {
        auto uri = t.data->value("uri", "");
        auto user = t.data->value("user", "");

        // Need to respond with error code.
        if (user.size == 0 || uri.size == 0) return;
        
        SimpleWeb::CaseInsensitiveMultimap header;
        
        client.sessions.set(j);
        string sid = j["sid"];
        string enc_str = j["signature"];

        // Set header with session id and x-token, then redirect.
        header.emplace("Location", uri);
        header.emplace("x-session-id", sid);
        header.emplace("x-access-token", enc_str);
        
        t.response->write(SimpleWeb::StatusCode::redirection_found, header);  
      }
    };
  }

  template<typename T>
  rxweb::middleware<T> getSession(rxweb::server<T>& server, store::storage::redis::Client& client) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "GET_SESSION"); },
      [](const rxweb::task<T>& t) {
        // TODO: Should really read from header
        auto enc_str = t.data->value("x-access-token", "");

        // Need to respond with error code.
        if (enc_str.size == 0) return;
        
        client.sessions.get(sid, enc_str, [](pair<string, shared_ptr<jwt::jwt_object>>& pa){
          if (pa.first.size() > 0) {
            // cerr << pa.first << endl;
            return;
          }

          /*
          // Valid user
          auto obj = *(pa.second);
          cout << obj.header() << endl;
          cout << obj.payload() << endl;
          */
         
        });

      }
    };
  }
}
