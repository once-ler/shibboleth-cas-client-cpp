#pragma once

#include "shibboleth-cas-client-cpp/src/common/util.hpp"

using namespace shibboleth::cas::common; 

namespace shibboleth::cas::middleware {
  
  template<typename T>
  rxweb::middleware<T> validateTicket(rxweb::server<T>& server,const json& config_j, const RS256KeyPair& rs256KeyPair) {
    
    return {
      [](const rxweb::task<T>& t) { return (t.type == "VALIDATE_TICKET"); },
      [&](const rxweb::task<T>& t) {
        auto ticket = getQueryStringVal<T>(t.request, "ticket");
        auto redirect = getQueryStringVal<T>(t.request, "redirect"); 

        string serviceProvider = config_j.value("serviceProvider", "");
        std::pair<string, string> finalDest = getFinalDestUrl<T>(t.request, config_j);
        
        string uri = fmt::format("{0}/cas/serviceValidate?service={1}&ticket={2}",
          serviceProvider,
          finalDest.first,
          ticket
        );

        auto j = apiCall(uri, "GET");

        parseValidationResponse(j);

        // Asymmetric encryption will be used if private key is provided.
        j["private_key"] = rs256KeyPair.privateKey;

        auto enc_str = createJwt(j);

        j["uri"] = redirect;

        auto nextTask = t;
        *(nextTask.data) = j;
        nextTask.type = "CREATE_SESSION";
        server.dispatch(nextTask);
        
      }
    };

  }

}
