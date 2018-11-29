#include "shibboleth-cas-client-cpp/src/server.hpp"

using namespace shibboleth::cas::server;

auto getConfig = [] {
  ifstream i("resources/config.json");
  json j;
  i >> j;
  return j;
};

auto main( const int argc, const char *const argv[] ) -> int {
  
  auto config_j = getConfig();

  start(config_j);

  return 0;  
}
