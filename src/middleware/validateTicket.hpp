#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common; 

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> validateTicket(rxweb::server<T>& server,const json& config_j) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "VALIDATE_TICKET"); },
      [&](const rxweb::task<T>& t) {
        auto queries = t.request->parse_query_string();

        string ticket = "";
        auto it = queries.find("ticket");
        if (it != queries.end())
          ticket = it->second;

        string serviceProvider = config_j.value("serviceProvider", "");
        string finalDest = config_j.value("finalDest", "");

        string uri = fmt::format("{0}/cas/serviceValidate?service={1}&ticket={2}",
          serviceProvider,
          finalDest,
          ticket
        );

        auto j = apiCall(uri, "GET");

        SimpleWeb::CaseInsensitiveMultimap header{{"Content-Type", "application/json"}};
        t.response->write(SimpleWeb::StatusCode::success_ok, j.dump(2), header);

      }
    };

  }

}
