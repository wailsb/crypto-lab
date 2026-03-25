

cmake_minimum_required(VERSION 3.10)
project(CryptoLab Tests)

set(CMAKE_CXX_STANDARD 17)

add_executable(crypto-lab 
    main.cpp
)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(Tests
    Tests/cesartest.cpp
    Classiques/Cesar/cesar.cpp
)

target_link_libraries(Tests 
    ${GTEST_LIBRARIES}
    pthread
)