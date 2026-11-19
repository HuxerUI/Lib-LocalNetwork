cmake_minimum_required(VERSION 3.20)

# CMake initializes Apple deployment defaults during the first project() call.
# Explicit settings and toolchains retain ownership of their target platform.
if (CMAKE_HOST_APPLE AND (NOT CMAKE_SYSTEM_NAME OR CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        AND NOT CMAKE_TOOLCHAIN_FILE AND "$ENV{CMAKE_TOOLCHAIN_FILE}" STREQUAL ""
        AND NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET AND "$ENV{MACOSX_DEPLOYMENT_TARGET}" STREQUAL "")
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum macOS deployment target")
endif ()

project(example_local_network VERSION 0.1.0 LANGUAGES NONE)

include("${CMAKE_CURRENT_SOURCE_DIR}/HuxerUIProject.cmake")
if (HUXERUI_PROJECT_PLAN_ONLY)
    return()
endif ()

file(GLOB_RECURSE APP_SOURCE_FILES CONFIGURE_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)
if (NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    if (WIN32)
        list(APPEND APP_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/platform/windows/main.cpp")
    elseif (APPLE AND NOT IOS)
        list(APPEND APP_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/main.cpp")
    elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND APP_SOURCE_FILES "${CMAKE_CURRENT_SOURCE_DIR}/platform/linux/main.cpp")
    endif ()
endif ()

huxerui_add_app(example_local_network
        SOURCES
            ${APP_SOURCE_FILES}
        RESOURCES
            resources
        RESOURCE_NAMESPACE
            app
        ${HUXERUI_APP_RESOURCE_OUTPUT_ARGUMENTS}
        BUNDLE_NAME
            "LocalNetwork Preview"
        BUNDLE_IDENTIFIER
            "org.huxerui.lib.localnetwork.preview"
)

huxerui_configure_project_app(example_local_network)

huxerui_use_library(example_local_network
        TARGET HuxerUI::LocalNetwork
        PATH "${CMAKE_CURRENT_SOURCE_DIR}/../.."
)

if (TARGET MbedTLS::mbedcrypto)
    target_compile_definitions(example_local_network PRIVATE HUXERUI_LOCALNETWORK_PREVIEW_TLS)
    target_link_libraries(example_local_network PRIVATE MbedTLS::mbedcrypto)
endif ()

if (WIN32 AND NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    target_compile_definitions(example_local_network PRIVATE NOMINMAX)
    target_link_libraries(example_local_network PRIVATE crypt32 shell32 iphlpapi ws2_32)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    enable_language(OBJCXX)
    set(wifi_settings "${CMAKE_CURRENT_SOURCE_DIR}/platform/macos/wifi_settings.mm")
    target_sources(example_local_network PRIVATE "${wifi_settings}")
    set_source_files_properties("${wifi_settings}" PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
    set_target_properties(example_local_network PROPERTIES OBJCXX_STANDARD 20 OBJCXX_STANDARD_REQUIRED ON)
    target_link_libraries(example_local_network PRIVATE "-framework AppKit")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(PREVIEW_GLIB QUIET IMPORTED_TARGET glib-2.0)
    endif ()
    if (TARGET PkgConfig::PREVIEW_GLIB)
        target_compile_definitions(example_local_network PRIVATE HUXERUI_LOCALNETWORK_PREVIEW_LINUX_SETTINGS)
        target_link_libraries(example_local_network PRIVATE PkgConfig::PREVIEW_GLIB)
    endif ()
endif ()

if ((WIN32 OR ANDROID OR IOS OR CMAKE_SYSTEM_NAME MATCHES "^(Darwin|Linux)$") AND NOT HUXERUI_LIBRARY_GRAPH_ONLY)
    include(cmake/PreviewQr.cmake)
    huxerui_localnetwork_preview_qr()
    target_compile_definitions(example_local_network PRIVATE HUXERUI_LOCALNETWORK_PREVIEW_QR)
    target_link_libraries(example_local_network PRIVATE ZXing::ZXing)
    if (IOS)
        include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/LocalNetworkIosArchives.cmake")
        huxerui_localnetwork_bundle_ios_archives(example_local_network ZXing::ZXing)
        enable_language(OBJCXX)
        set(qr_camera "${CMAKE_CURRENT_SOURCE_DIR}/platform/ios/qr_camera.mm")
        target_sources(example_local_network PRIVATE "${qr_camera}")
        set_source_files_properties("${qr_camera}" PROPERTIES COMPILE_OPTIONS "-fobjc-arc")
        set_target_properties(example_local_network PROPERTIES OBJCXX_STANDARD 20 OBJCXX_STANDARD_REQUIRED ON)
    endif ()
endif ()
