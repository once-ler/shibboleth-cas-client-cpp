#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {
  template<typename T>
  rxweb::middleware<T> createSession(rxweb::server<T>& server, store::storage::redis::Client& client) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "CREATE_SESSION"); },
      [](const rxweb::task<T>& t) {
        auto uri = t.data->value("uri", "");

        // From post validation of the ticket.
        auto user = t.data->value("user", "");

        // Need to respond with error code.
        if (user.size == 0 || uri.size == 0) {
          t.response->write(SimpleWeb::StatusCode::client_error_unauthorized);
          return;
        }
        
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

        auto sidIt = t.request->header.find("sid");
        auto encIt = t.request->header.find("x-access-token");
        auto endIt = t.request->header.end();

        if (sidIt == endIt || encIt == endIt) {
          t.response->write(SimpleWeb::StatusCode::client_error_unauthorized);
          return;
        }

        string sid = sidIt->second, enc_str = encIt->second;

        client.sessions.get(sid, enc_str, [](pair<string, shared_ptr<jwt::jwt_object>>& pa){
          if (pa.first.size() > 0) {
            t.response->write(SimpleWeb::StatusCode::client_error_unauthorized);
            return;
          }

          /*
          // Valid user
          auto obj = *(pa.second);
          cout << obj.header() << endl;
          cout << obj.payload() << endl;
          */

          // Need to convert payload to string, parse to json, and then get user info.
          /*
          SimpleWeb::CaseInsensitiveMultimap header{{"Content-Type", "application/json"}};
          t.response->write(SimpleWeb::StatusCode::success_ok, j.dump(2), header); 
          */
        });

      }
    };
  }
}
