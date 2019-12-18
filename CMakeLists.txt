if (POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
    project(ROT13_SERVER VERSION 0.1.0)
else()
    project(ROT13_SERVER)
endif()

cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
cmake_policy(VERSION 3.2)

if (POLICY CMP0063)
    cmake_policy(SET CMP0063 OLD) # Do not allow hidden visibility for static libs
endif()

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS NO_OUTPUT_DIRS)

# The required C++ Standard for Server++ is C++14.
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set (ROT13_SERVER_PUBLIC_SOURCE_FILES
    src/connection.cpp
    src/rot13_server.cpp
)

set (ROT13_SERVER_PUBLIC_HEADER_FILES
    include/connection.hpp
)

add_executable(rot13_server
    ${ROT13_SERVER_PUBLIC_HEADER_FILES}
    ${ROT13_SERVER_PUBLIC_SOURCE_FILES}
)

target_include_directories(rot13_server 
    PRIVATE 
        include
)

target_link_libraries(rot13_server
    CONAN_PKG::serverpp
    CONAN_PKG::telnetpp
    CONAN_PKG::boost_range
)
