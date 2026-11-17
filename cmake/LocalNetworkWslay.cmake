function(huxerui_localnetwork_configure_wslay)
    if (TARGET localnetwork_wslay)
        return()
    endif ()

    set(download_dir "${CMAKE_BINARY_DIR}/_deps/localnetwork-wslay")
    set(archive "${download_dir}/wslay-1.1.1.tar.gz")
    set(source_dir "${download_dir}/wslay-release-1.1.1/lib")
    if (NOT EXISTS "${archive}.extracted" OR NOT EXISTS "${source_dir}/wslay_event.c")
        file(MAKE_DIRECTORY "${download_dir}")
        file(DOWNLOAD
                "https://codeload.github.com/tatsuhiro-t/wslay/tar.gz/refs/tags/release-1.1.1"
                "${archive}"
                EXPECTED_HASH SHA256=7b9f4b9df09adaa6e07ec309b68ab376c0db2cfd916613023b52a47adfda224a
                TLS_VERIFY ON
                TIMEOUT 120
        )
        file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${download_dir}")
        file(WRITE "${archive}.extracted" "1.1.1")
    endif ()

    # Build just the protocol library. Use the host toolchain's warning and CMake policies.
    add_library(localnetwork_wslay STATIC
            "${source_dir}/wslay_event.c"
            "${source_dir}/wslay_frame.c"
            "${source_dir}/wslay_net.c"
            "${source_dir}/wslay_queue.c"
            "${source_dir}/wslay_stack.c"
    )
    target_include_directories(localnetwork_wslay SYSTEM PUBLIC "${source_dir}/includes")
    target_compile_definitions(localnetwork_wslay PUBLIC WSLAY_VERSION="1.1.1")
    set_target_properties(localnetwork_wslay PROPERTIES C_STANDARD 99 POSITION_INDEPENDENT_CODE ON)
    if (WIN32)
        target_compile_definitions(localnetwork_wslay PRIVATE HAVE_WINSOCK2_H)
        target_link_libraries(localnetwork_wslay PRIVATE ws2_32)
        if (MSVC)
            target_compile_options(localnetwork_wslay PRIVATE /FIbasetsd.h)
            target_compile_definitions(localnetwork_wslay PRIVATE ssize_t=SSIZE_T)
        endif ()
    else ()
        target_compile_definitions(localnetwork_wslay PRIVATE HAVE_ARPA_INET_H)
    endif ()
endfunction()
