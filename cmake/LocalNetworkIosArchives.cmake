include_guard(GLOBAL)

function(huxerui_localnetwork_bundle_ios_archives target)
    find_program(LOCALNETWORK_LIBTOOL libtool REQUIRED)
    set(dependency_archives)
    foreach (dependency IN LISTS ARGN)
        list(APPEND dependency_archives "$<TARGET_FILE:${dependency}>")
    endforeach ()

    # The Xcode host links a combined HuxerUI archive. Regenerate the target archive when a bundled archive changes.
    set(rebuild_source "${CMAKE_CURRENT_BINARY_DIR}/${target}_ios_archive_dependencies.cpp")
    add_custom_command(OUTPUT "${rebuild_source}"
            COMMAND "${CMAKE_COMMAND}" -E touch "${rebuild_source}"
            DEPENDS ${ARGN}
            VERBATIM
    )
    target_sources("${target}" PRIVATE "${rebuild_source}")
    set(archive "$<TARGET_FILE:${target}>")
    add_custom_command(TARGET "${target}" POST_BUILD
            COMMAND "${LOCALNETWORK_LIBTOOL}" -static -o "${archive}.combined" "${archive}" ${dependency_archives}
            COMMAND "${CMAKE_COMMAND}" -E rename "${archive}.combined" "${archive}"
            VERBATIM
    )
endfunction()
