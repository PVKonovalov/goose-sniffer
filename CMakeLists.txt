cmake_minimum_required(VERSION 3.16)
project(goose-sniffer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(goose-sniffer main.cpp)

find_package(PCAP QUIET)
set(PCAP_RESOLVED FALSE)

if(PCAP_FOUND)
	if(TARGET PCAP::PCAP)
		target_link_libraries(goose-sniffer PRIVATE PCAP::PCAP)
	else()
		target_include_directories(goose-sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
		target_link_libraries(goose-sniffer PRIVATE ${PCAP_LIBRARIES})
	endif()
	set(PCAP_RESOLVED TRUE)
endif()

if(NOT PCAP_RESOLVED AND UNIX)
	find_package(PkgConfig QUIET)
	if(PkgConfig_FOUND)
		pkg_check_modules(PCAP_PKG QUIET libpcap)
		if(PCAP_PKG_FOUND)
			target_include_directories(goose-sniffer PRIVATE ${PCAP_PKG_INCLUDE_DIRS})
			target_link_directories(goose-sniffer PRIVATE ${PCAP_PKG_LIBRARY_DIRS})
			target_link_libraries(goose-sniffer PRIVATE ${PCAP_PKG_LIBRARIES})
			target_compile_options(goose-sniffer PRIVATE ${PCAP_PKG_CFLAGS_OTHER})
			set(PCAP_RESOLVED TRUE)
		endif()
	endif()
endif()

if(NOT PCAP_RESOLVED)
	if(APPLE)
		set(PCAP_INCLUDE_HINTS /opt/homebrew/opt/libpcap/include /usr/local/opt/libpcap/include)
		set(PCAP_LIBRARY_HINTS /opt/homebrew/opt/libpcap/lib /usr/local/opt/libpcap/lib)
	endif()

	find_path(
		PCAP_INCLUDE_DIR
		NAMES pcap.h
		HINTS ${PCAP_INCLUDE_HINTS}
	)
	find_library(
		PCAP_LIBRARY
		NAMES pcap
		HINTS ${PCAP_LIBRARY_HINTS}
	)

	if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
		target_include_directories(goose-sniffer PRIVATE ${PCAP_INCLUDE_DIR})
		target_link_libraries(goose-sniffer PRIVATE ${PCAP_LIBRARY})
		set(PCAP_RESOLVED TRUE)
	endif()
endif()

if(NOT PCAP_RESOLVED)
	message(FATAL_ERROR "libpcap not found. Install libpcap-dev (Linux) or brew install libpcap (macOS).")
endif()

