function(frego_warnings target)
  target_compile_options(${target} PRIVATE
    -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor
    $<$<BOOL:${FREGO_WERROR}>:-Werror>)
endfunction()

# Version and channel, compiled into every binary (DESIGN §3, build channel).
function(frego_version target)
  target_compile_definitions(${target} PRIVATE
    FREGO_VERSION="${FREGO_VERSION_STRING}" FREGO_CHANNEL="${FREGO_CHANNEL}")
endfunction()
