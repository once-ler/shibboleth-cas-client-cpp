#pragma once

#include <fstream>
#include <chrono>
#include "rxweb/src/rxweb.hpp"
#include "rxweb/src/server.hpp"
#include "spdlog/fmt/fmt.h"
#include "shibboleth-cas-client-cpp/src/common/apiCall.hpp"
#include "pugixml.hpp"
#include "jwt/jwt.hpp"
#include "uuid.hh"

using json = nlohmann::json;
using WebTask = rxweb::task<SimpleWeb::HTTP>;
using SocketType = SimpleWeb::ServerBase<SimpleWeb::HTTP>;
using HTTPRequest = std::shared_ptr<SocketType::Request>;
using HTTPResponse = std::shared_ptr<SocketType::Response>;

namespace shibboleth::cas::common {

  struct Time {
    std::chrono::system_clock::time_point timePoint;
    std::time_t epochTime;
    std::string timeString;
  }

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

  string generate_uuid(int vers = UUID_MAKE_V4) {
    uuid id;
    id.make(vers);
    const char* sid = id.string();
    std::string r(sid);
    delete sid;

    return std::move(r);
  }

  string generate_uuid_v3(const char* url) {
    uuid id;
    uuid id_ns;

    id_ns.load("ns:URL");
    id.make(UUID_MAKE_V3, &id_ns, url);
    const char* sid = id.string();
    std::string r(sid);
    delete sid;

    return std::move(r);
  }

  auto getExpirationTime = [](int num_hr) {
    auto exp = std::chrono::system_clock::now() + std::chrono::hours{num_hr};
    std::time_t exp_time = std::chrono::system_clock::to_time_t(exp); 
    string ts = std::put_time(std::localtime(&exp_time), "%F %T");
    
    return Time{ exp, exp_time, ts };
  }

  auto createJwt = [](const json& j) {
    if (j["user"].is_null())
      return j;

    auto user = j["user"].get<string>();
    auto shhh = generate_uuid();
    auto et = getExpirationTime(24);

    j["secret"] = shhh;
    j["expire"] = static_cast<int64_t>(et.epochTime * 1000);
    j["expire_ts"] = et.timeString; 
    j["user_id"] = generate_uuid_v3(user.c_str());

    jwt::jwt_object obj{algorithm("hs256"), secret(shhh),
      payload(
        {
          { "iss", "shibboleth::cas" },
          { "exp", et.timePoint },
          { "user", user }
        }
      )}

  }

}
