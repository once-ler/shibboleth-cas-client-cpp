#pragma once

#include "shibboleth-cas-client/src/common/util.hpp"

using namespace shibboleth::cas::common;

namespace shibboleth::cas::session {

  class RedisStore {
  public:
    RedisStore(const RedisStore& r) = default;
    RedisStore(RedisStore&& r) = default;
    RedisStore& operator=(const RedisStore& r) = default;
    RedisStore& operator=(RedisStore&& r) = default;

    RedisStore(string host_ = "127.0.0.1", int port_ = 6379) {
      client.connect(host_, port_, [](const std::string& host, std::size_t port, cpp_redis::client::connect_state status) {
        if (status == cpp_redis::client::connect_state::dropped) {
          std::cerr << "client disconnected from " << host << ":" << port << std::endl;
        }
      });      
    }

    /*
      The value stored per the session id is the key to the encrypted string.
    */
    get(string sid, string enc_str) {
      auto j = json(nullptr);

      client.get(sid, [](cpp_redis::reply& reply) {
        if (reply.is_string()) {
          auto key = reply.as_string();
          auto obj = decryptJwt(key, enc_str);
        }
      
      });
      
      client.commit();
    }

  private:
    cpp_redis::client client;    
  };

}
