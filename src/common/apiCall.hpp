#pragma once

#include <iostream>
#include <curlpp/cURLpp.hpp>
#include <curlpp/Easy.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/Exception.hpp> 
#include <curlpp/Infos.hpp>
#include "json.hpp"

using json = nlohmann::json;

namespace shibboleth::cas::common {

  json apiCall(string url, string method, string data = "", std::map<string, string> header = {}) {
    json j;
    curlpp::Cleanup cleaner;
    curlpp::Easy request;

    // Headers:
    std::list<std::string> cu_header;
    for_each(header.begin(), header.end(), [&cu_header](auto& e) {
      auto h = string{e.first + ": " + e.second};
      cu_header.push_back(h); 
    });

    request.setOpt(new curlpp::options::HttpHeader(cu_header));

    // Url
    request.setOpt(new curlpp::options::Url(url.c_str()));

    // Method
    request.setOpt(curlpp::options::CustomRequest(method.c_str()));
  
    // Request Body
    if (data.size() > 0){
      std::regex reg("\\r\\n|\\r|\\n");	
      data = std::regex_replace(data, reg, "");

      request.setOpt(new curlpp::options::PostFields(data));
      request.setOpt(new curlpp::options::PostFieldSize(data.size()));
    }

    ostringstream oss;
    curlpp::options::WriteStream ws(&oss);
    request.setOpt(ws);

    try {
      j["request"] = data;

      request.perform();
      
      string resp = oss.str();
      
      j["statusCode"] = curlpp::infos::ResponseCode::get(request);
      j["response"] = resp;
    } catch (curlpp::LogicError& e) {
        j["response"] = e.what();
      }
      catch (curlpp::RuntimeError& e) {
        j["response"] = e.what();
      }
      catch (std::runtime_error& e) {
        j["response"] = e.what();
      } 
    
    return j; 
  }
}
