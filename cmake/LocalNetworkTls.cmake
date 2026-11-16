function(huxerui_localnetwork_configure_tls)
    if (TARGET MbedTLS::mbedtls)
        return()
    endif ()

    set(ENABLE_PROGRAMS OFF)
    set(ENABLE_TESTING OFF)
    set(USE_SHARED_MBEDTLS_LIBRARY OFF)
    set(USE_STATIC_MBEDTLS_LIBRARY ON)
    set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON)
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)

    # Download in the main configure process. Android's CMake 3.22 delegates FetchContent to a nested Ninja build.
    set(version 3.6.7)
    set(download_dir "${CMAKE_BINARY_DIR}/_deps/localnetwork-tls")
    set(archive "${download_dir}/mbedtls-${version}.tar.bz2")
    set(source_dir "${download_dir}/mbedtls-${version}")
    if (NOT EXISTS "${archive}.extracted" OR NOT EXISTS "${source_dir}/CMakeLists.txt")
        file(MAKE_DIRECTORY "${download_dir}")
        file(DOWNLOAD
                "https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-${version}/mbedtls-${version}.tar.bz2"
                "${archive}"
                EXPECTED_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
                TLS_VERIFY ON
                TIMEOUT 120
        )
        file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${download_dir}")
        file(WRITE "${archive}.extracted" "${version}\n")
    endif ()
    add_subdirectory("${source_dir}" "${CMAKE_CURRENT_BINARY_DIR}/mbedtls" EXCLUDE_FROM_ALL)
endfunction()
