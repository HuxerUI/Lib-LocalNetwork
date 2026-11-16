function(huxerui_localnetwork_preview_qr)
    if (TARGET ZXing::ZXing)
        return()
    endif ()

    set(ZXING_C_API OFF)
    set(ZXING_EXAMPLES OFF)
    set(ZXING_WRITERS OLD)
    set(ZXING_ENABLE_1D OFF)
    set(ZXING_ENABLE_AZTEC OFF)
    set(ZXING_ENABLE_DATAMATRIX OFF)
    set(ZXING_ENABLE_MAXICODE OFF)
    set(ZXING_ENABLE_PDF417 OFF)
    set(BUILD_SHARED_LIBS OFF)
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(version 3.0.2)
    set(download_dir "${CMAKE_BINARY_DIR}/_deps/localnetwork-qr")
    set(archive "${download_dir}/zxing-cpp-${version}.tar.gz")
    set(source_dir "${download_dir}/zxing-cpp-${version}")
    if (NOT EXISTS "${archive}.extracted" OR NOT EXISTS "${source_dir}/CMakeLists.txt")
        file(MAKE_DIRECTORY "${download_dir}")
        file(DOWNLOAD
                "https://github.com/zxing-cpp/zxing-cpp/releases/download/v${version}/zxing-cpp-${version}.tar.gz"
                "${archive}"
                EXPECTED_HASH SHA256=e957f13e2ad4e31badb3d9af3f6ba8999a3ca3c9cc4d6bafc98032f9cce1a090
                TLS_VERIFY ON
                TIMEOUT 120
        )
        file(ARCHIVE_EXTRACT INPUT "${archive}" DESTINATION "${download_dir}")
        file(WRITE "${archive}.extracted" "${version}\n")
    endif ()
    add_subdirectory("${source_dir}" "${CMAKE_CURRENT_BINARY_DIR}/zxing" EXCLUDE_FROM_ALL)
endfunction()
