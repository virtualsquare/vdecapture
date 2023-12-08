cmake_minimum_required(VERSION 3.12)
project(vdecapture
		VERSION 0.0.1
		DESCRIPTION "Capture vde traffic in pcap format"
		HOMEPAGE_URL "https://github.com/virtualsquare/vdecapture"
		LANGUAGES C)

set(HEADERS_REQUIRED libvdeplug.h pcap/pcap.h)
include(CheckIncludeFile)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

find_library(TESTVDEPLUG vdeplug)
if(NOT TESTVDEPLUG)
  message(FATAL_ERROR "libvdeplug not found")
endif()

include(GNUInstallDirs)
add_definitions(-D_GNU_SOURCE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_FORTIFY_SOURCE=2 -O2 -pedantic -Wall -Wextra")
add_executable(vdecapture vdecapture.c)
target_link_libraries(vdecapture vdeplug)
install(TARGETS vdecapture
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}"
    -DCADO_SPOOL_DIR=${CADO_SPOOL_DIR}
    -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake"
  )
