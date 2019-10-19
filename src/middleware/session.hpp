#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

namespace shibboleth::cas::middleware {

  template<typename T>
  rxweb::middleware<T> createSession(rxweb::server<T>& server, store::storage::redis::Client& client) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "CREATE_SESSION"); },
      [&](const rxweb::task<T>& t) {
        auto j = *(t.data);
      
        string uri = j["uri"];
        auto user = j.value("user", "");

        if (user.size() == 0) {
          t.response->write(SimpleWeb::StatusCode::client_error_unauthorized);
          return;
        }
        
        SimpleWeb::CaseInsensitiveMultimap header;
        
        client.sessions.set(j);
        string sid = j["sid"];
        string enc_str = j["signature"];

        // Attach the token with the redirect uri.
        string addTokenToUri = "x-access-token=" + enc_str;
        if (uri.find("?") != string::npos) {
          uri.append("&");
        } else {
          uri.append("?");
        }
        uri.append(addTokenToUri);

        // Set header with session id and x-token, then redirect.
        header.emplace("Location", uri);
        // Set-Cookie: ...; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=8080
        header.emplace("Set-Cookie", "x-session-id=" + sid + "; HttpOnly; Path=/; SameSite=Lax");
        header.emplace("Set-Cookie", "x-access-token=" + enc_str + "; HttpOnly; Path=/; SameSite=Lax");

        t.response->write(SimpleWeb::StatusCode::redirection_found, header);  
      }
    };
  }

  template<typename T>
  rxweb::middleware<T> getSession(rxweb::server<T>& server, store::storage::redis::Client& client) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "GET_SESSION"); },
      [&](const rxweb::task<T>& t) {

        auto cookies = getCookies<T>(t.request);

        auto sidIt = cookies.find("x-session-id");
        auto encIt = cookies.find("x-access-token");
        auto endIt = cookies.end();
        
        if (sidIt == endIt || encIt == endIt) {
          sendAccessDenied<T>(t.response);
          return;
        }

        string sid = sidIt->second, enc_str = encIt->second;

        client.sessions.get(sid, enc_str, [&t](pair<string, shared_ptr<jwt::jwt_object>>& pa){
          if (pa.first.size() > 0) {
            sendAccessDenied<T>(t.response);
            return;
          }

          auto obj = *(pa.second);

          ostringstream oss;
          oss << obj.header();
          auto h = json::parse(oss.str());
          oss.str("");
          oss << obj.payload();
          auto p = json::parse(oss.str());
          json j = {
            {"header", h},
            {"payload", p}
          };
          auto j_str = j.dump(2);

          SimpleWeb::CaseInsensitiveMultimap header{
            {"Content-Type", "application/json"}
          };          
          t.response->write(SimpleWeb::StatusCode::success_ok, j_str, header);
        });

      }
    };
  }
}
