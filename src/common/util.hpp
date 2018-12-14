#pragma once

#include <fstream>
#include <chrono>
#include "rxweb/src/rxweb.hpp"
#include "rxweb/src/server.hpp"
#include "spdlog/fmt/fmt.h"
#include "pugixml.hpp"
#include "shibboleth-cas-client-cpp/src/common/apiCall.hpp"
#include "store.storage.redis/src/redis_client.hpp"
#include "store.common/src/web_token.hpp"

using RedisClient = store::storage::redis::Client;
using json = nlohmann::json;
using WebTask = rxweb::task<SimpleWeb::HTTP>;
using SocketType = SimpleWeb::ServerBase<SimpleWeb::HTTP>;
using HTTPRequest = std::shared_ptr<SocketType::Request>;
using HTTPResponse = std::shared_ptr<SocketType::Response>;

using namespace store::common;

namespace shibboleth::cas::common {

  auto parseValidationResponse = [](json& j) {

    string p{"/cas:serviceResponse/cas:authenticationSuccess/cas:user"};
        
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(j["response"].get<string>().c_str());

    if (result) {
      try {
        pugi::xpath_node user = doc.select_node(p.c_str());
        if (user) {
          j["user"] = user.node().child_value();
        } else {
          j["error"] = "Unauthorized";  
        }
      } catch (const pugi::xpath_exception& e) {
        j["error"] = e.what();
      } catch (...) {
        j["error"] = "Unexpected error";
      }
    } else {
      j["error"] = "Couldn't parse xml string";
    }

    return j;
  };

  template<typename A>
  auto getFinalDestUrl = [](shared_ptr<typename SimpleWeb::ServerBase<A>::Request> request, const json& config_j) {
    string protocol = "https";
    if (std::is_same<A, SimpleWeb::HTTP>::value == true) {
      protocol = "http";
    }

    auto queries = request->parse_query_string();
    string host = config_j.value("host", "localhost");
    int port = config_j.value("port", 3000);

    string uri_req = "";
    auto it = queries.find("redirect");
    if (it != queries.end())
      uri_req = it->second;
    else
      uri_req = fmt::format("{}://{}:{:d}/session",
        protocol, host, port          
      );    

    return fmt::format("{}://{}:{:d}/validate?redirect={}",
      protocol, host, port, uri_req     
    );

  };

  template<typename A>
  auto getQueryStringVal = [](shared_ptr<typename SimpleWeb::ServerBase<A>::Request> request, string key) {
    auto queries = request->parse_query_string();

    string val = "";
    auto it = queries.find(key);
    if (it != queries.end())
      val = it->second;

    return val;
  };

  template<typename A>
  auto sendAccessDenied = [](shared_ptr<typename SimpleWeb::ServerBase<A>::Response> response) {
    string text = "Access Denied!";
    SimpleWeb::CaseInsensitiveMultimap header{
      {"Content-Type", "text/plain"}
    };          
    
    response->write(SimpleWeb::StatusCode::client_error_unauthorized, text, header);
  };

}
