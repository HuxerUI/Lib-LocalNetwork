cmake_minimum_required(VERSION 3.20)

# CMake initializes Apple deployment defaults during the first project() call.
# Explicit settings and toolchains retain ownership of their target platform.
if (CMAKE_HOST_APPLE AND (NOT CMAKE_SYSTEM_NAME OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        AND NOT CMAKE_TOOLCHAIN_FILE AND "$ENV{CMAKE_TOOLCHAIN_FILE}" STREQUAL ""
        AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET AND "$ENV{MACOSX_DEPLOYMENT_TARGET}" STREQUAL "")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum macOS deployment target")
endif ()

project(local_network VERSION 0.1.0 LANGUAGES NONE)

include("${CMAKE_CURRENT_SOURCE_DIR}/HuxerUIProject.cmake")
if (HUXERUI_PROJECT_PLAN_ONLY)
    return()
endif ()

if (APPLE AND NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    enable_language(OBJCXX)
endif ()

file(GLOB_RECURSE LIBRARY_SOURCE_FILES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)
if (ANDROID)
    file(GLOB_RECURSE LIBRARY_ANDROID_SOURCE_FILES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/android/src/main/cpp/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/android/src/main/cpp/*.cc"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/android/src/main/cpp/*.cxx"
    )
    list(APPEND LIBRARY_SOURCE_FILES ${LIBRARY_ANDROID_SOURCE_FILES})
endif ()
if (WIN32)
    file(GLOB_RECURSE LIBRARY_WINDOWS_SOURCE_FILES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/src/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/src/*.cc"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/src/*.cxx"
    )
    list(APPEND LIBRARY_SOURCE_FILES ${LIBRARY_WINDOWS_SOURCE_FILES})
endif ()
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB_RECURSE LIBRARY_LINUX_SOURCE_FILES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/linux/src/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/linux/src/*.cc"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/linux/src/*.cxx"
    )
    list(APPEND LIBRARY_SOURCE_FILES ${LIBRARY_LINUX_SOURCE_FILES})
endif ()
if (APPLE AND NOT IOS)
    file(GLOB_RECURSE LIBRARY_MACOS_SOURCE_FILES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/src/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/src/*.cc"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/src/*.cxx"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/src/*.mm"
    )
    list(APPEND LIBRARY_SOURCE_FILES ${LIBRARY_MACOS_SOURCE_FILES})
endif ()
if (IOS)
    list(APPEND LIBRARY_SOURCE_FILES
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/ios/src/discovery.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/ios/src/wifi.mm"
    )
endif ()
if (EMSCRIPTEN)
    file(GLOB_RECURSE LIBRARY_WEB_SOURCE_FILES CONFIGURE_DEPENDS
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/web/src/*.cpp"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/web/src/*.cc"
            "${CMAKE_CURRENT_SOURCE_DIR}/platform/web/src/*.cxx"
    )
    list(APPEND LIBRARY_SOURCE_FILES ${LIBRARY_WEB_SOURCE_FILES})
endif ()

huxerui_add_library(huxerui_localnetwork
        SOURCES
            ${LIBRARY_SOURCE_FILES}
        RESOURCES
            resources
        RESOURCE_NAMESPACE
            huxerui_localnetwork
)

add_library(HuxerUI::LocalNetwork ALIAS huxerui_localnetwork)

if (HUXERUI_LIBRARY_GRAPH_ONLY)
    return()
endif ()

target_include_directories(huxerui_localnetwork PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
        "$<INSTALL_INTERFACE:include>"
)

if (WIN32)
    target_compile_definitions(huxerui_localnetwork PRIVATE NOMINMAX)
    target_link_libraries(huxerui_localnetwork PRIVATE ws2_32 dnsapi iphlpapi wlanapi)
elseif (ANDROID)
    target_link_libraries(huxerui_localnetwork PRIVATE android)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(LOCALNETWORK_AVAHI QUIET IMPORTED_TARGET avahi-client)
        pkg_check_modules(LOCALNETWORK_GIO QUIET IMPORTED_TARGET gio-2.0)
    endif ()
    if (TARGET PkgConfig::LOCALNETWORK_AVAHI)
        target_compile_definitions(huxerui_localnetwork PRIVATE HUXERUI_LOCALNETWORK_AVAHI)
        target_link_libraries(huxerui_localnetwork PRIVATE PkgConfig::LOCALNETWORK_AVAHI)
    endif ()
    if (TARGET PkgConfig::LOCALNETWORK_GIO)
        target_link_libraries(huxerui_localnetwork PRIVATE PkgConfig::LOCALNETWORK_GIO)
    endif ()
endif ()

if (WIN32 OR ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR TARGET PkgConfig::LOCALNETWORK_GIO)
    target_compile_definitions(huxerui_localnetwork PRIVATE HUXERUI_LOCALNETWORK_WIFI_SCAN HUXERUI_LOCALNETWORK_WIFI_JOIN)
elseif (IOS)
    target_compile_definitions(huxerui_localnetwork PRIVATE HUXERUI_LOCALNETWORK_WIFI_JOIN)
endif ()

if (IOS)
    set(wifi_source "${CMAKE_CURRENT_SOURCE_DIR}/platform/ios/src/wifi.mm")
    target_link_libraries(huxerui_localnetwork PRIVATE "-framework NetworkExtension")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(wifi_source "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/src/wifi.mm")
    target_link_libraries(huxerui_localnetwork PRIVATE "-framework CoreWLAN" "-framework CoreLocation")
endif ()
if (DEFINED wifi_source)
    set_source_files_properties("${wifi_source}" PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    set_target_properties(huxerui_localnetwork PROPERTIES OBJCXX_STANDARD 20 OBJCXX_STANDARD_REQUIRED ON)
endif ()

if (IOS OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_compile_definitions(huxerui_localnetwork PRIVATE HUXERUI_LOCALNETWORK_BONJOUR)
endif ()

if (WIN32 OR ANDROID OR IOS OR CMAKE_SYSTEM_NAME MATCHES "^(Darwin|Linux)$")
    include(cmake/LocalNetworkTls.cmake)
    huxerui_localnetwork_configure_tls()
    target_compile_definitions(huxerui_localnetwork PRIVATE HUXERUI_LOCALNETWORK_TLS)
    target_link_libraries(huxerui_localnetwork PRIVATE MbedTLS::mbedtls)
    if (IOS)
        huxerui_localnetwork_bundle_ios_tls(huxerui_localnetwork)
    endif ()
endif ()
