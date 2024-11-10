cmake_minimum_required(VERSION 3.5)

project(crabftp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(fs)

add_executable(crabftp
    main.cpp
    server.h
    server.cpp
)

add_executable(ls ls.cpp)
target_link_libraries(ls fs)
