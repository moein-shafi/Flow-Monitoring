cmake_minimum_required(VERSION 2.8)
project (Flow-Monitoring)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCES src/Main.cpp
    src/Flow.cpp)

set(HEADERS src/Flow.h
    src/writer/Writer.h
    src/writer/CSVWriter.h)

add_executable(Flow-Monitoring ${SOURCES} ${HEADERS})
target_link_libraries(Flow-Monitoring pcap)
