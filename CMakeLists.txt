cmake_minimum_required(VERSION 3.16)
project(DeepPacketInspectionSystem VERSION 2.5 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

# Multi-threaded DPI & IDS Engine
set(DPI_SOURCES
    src/dpi_mt.cpp
    src/ids_engine.cpp
    src/live_capture.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)

add_executable(dpi_engine ${DPI_SOURCES})

if(WIN32)
    target_link_libraries(dpi_engine PRIVATE ws2_32 iphlpapi)
endif()

# Basic Packet Analyzer
set(ANALYZER_SOURCES
    src/main.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
)
add_executable(packet_analyzer ${ANALYZER_SOURCES})
