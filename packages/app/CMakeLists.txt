cmake_minimum_required(VERSION 3.2)

project(shibboleth-cas-client VERSION 0.4.3 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_FLAGS "-v")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

find_package(OpenSSL)
find_package(Threads)
find_package(Boost 1.62.0 COMPONENTS thread date_time program_options filesystem system regex REQUIRED)
#find_package(PostgreSQL REQUIRED)

#set(HL7PARSER ${PROJECT_SOURCE_DIR}/../../hl7parser-json/include)
set(RXCPP ${PROJECT_SOURCE_DIR}/../../../RxCpp/Rx/v2/src)
#set(JSON_OLD ${PROJECT_SOURCE_DIR}/../../json/single_include)
set(JSON ${PROJECT_SOURCE_DIR}/../../../json/single_include/nlohmann)
set(RXWEB ${PROJECT_SOURCE_DIR}/../../../rx-web-cpp)
set(SIMPLE_WEB_SERVER ${PROJECT_SOURCE_DIR}/../../../Simple-Web-Server)
set(SIMPLE_WEBSOCKET_SERVER ${PROJECT_SOURCE_DIR}/../../../Simple-WebSocket-Server)
#set(LIBPQMXX ${PROJECT_SOURCE_DIR}/../../libpqmxx/include)
#set(STORE ${PROJECT_SOURCE_DIR}/../../Store-cpp)
#set(SPDLOG ${PROJECT_SOURCE_DIR}/../../spdlog/include)
#set(TDSPP ${PROJECT_SOURCE_DIR}/../../tdspp)
#set(CSV ${PROJECT_SOURCE_DIR}/../../fast-cpp-csv-parser)

include_directories(
  /usr/local/
  "${PROJECT_SOURCE_DIR}/../../../"
  "${RXCPP}"
  "${RXWEB}"
  "${SIMPLE_WEB_SERVER}" 
  "${SIMPLE_WEBSOCKET_SERVER}"
  "${JSON}"
)

link_directories(  
)

file(GLOB_RECURSE CPP_SOURCES "${PROJECT_SOURCE_DIR}/index.cpp")

add_executable(shibboleth-cas-client ${CPP_SOURCES})

target_link_libraries(
  shibboleth-cas-client 
  ${Boost_LIBRARIES} 
  Threads::Threads 
  OpenSSL::Crypto 
  OpenSSL::SSL  
)

# file(COPY "${PROJECT_SOURCE_DIR}/../resources" DESTINATION ${CMAKE_BINARY_DIR}/bin)
