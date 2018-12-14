// default: http://localhost:3000/auth will redirect to http://localhost:3000/session
// custom: http://localhost:3000/auth?redirect=http://localhost:4000/welcome
// custom: http://localhost:3000/auth?redirect=https://www.google.com

/*
g++ -std=c++11 -Wall -I ../../../Catch2/single_include -I ../../src -I ../../../json/single_include/nlohmann -o 000-default_redirect ../000-default_redirect.cpp catch_main.o
./000-default_redirect --success
*/
#include <catch2/catch.hpp>

using json = nlohmann::json;

SCENARIO( "Shibboleth client will forward request to federation-cas server for authentication", "[resource]" ) {

  GIVEN("A protected resource") {
    WHEN("Correctly authenticated") {
      // Resource to be the default page
      REQUIRE(a == b);

      GIVEN("A query to inspect the encrypted JWT") {
        // Shibboleth client will decrypt the token if a valid session exists in redis.
      }
    }

    WHEN("Incorrectly authenticated") {
      // Shibboleth client will return a 401 status code.
    }
  }
}

/****
 * 
 * For redis unit tests, please visit:
 * https://github.com/once-ler/Store-cpp/blob/master/store.storage.redis/test/000-basic-crud.cpp
 *
 ****/

/****
 * 
 * For jwt unit tests, please visit:
 * https://github.com/once-ler/Store-cpp/blob/master/store.storage.redis/test/001-jwt.cpp
 *
 ****/
