# The plugin registry is generated from FREGO_PLUGINS instead of using self-registering
# statics, which the linker silently drops from static libraries (DESIGN §4.3).
set(FREGO_PLUGIN_INCLUDES "")
set(FREGO_PLUGIN_CALLS "")
set(FREGO_PLUGIN_TARGETS "")
foreach(plugin IN LISTS FREGO_PLUGINS)
  string(REPLACE "_" "-" plugin_name ${plugin})
  string(APPEND FREGO_PLUGIN_INCLUDES "#include \"frego/plugins/${plugin}.hpp\"\n")
  string(APPEND FREGO_PLUGIN_CALLS "    registry.add(\"${plugin_name}\", &frego::plugins::make_${plugin});\n")
  list(APPEND FREGO_PLUGIN_TARGETS frego_plugin_${plugin})
endforeach()
configure_file(plugins.gen.cpp.in ${CMAKE_CURRENT_BINARY_DIR}/plugins.gen.cpp @ONLY)

add_executable(fregod main.cpp ${CMAKE_CURRENT_BINARY_DIR}/plugins.gen.cpp)
target_link_libraries(fregod PRIVATE frego_core frego_domain frego_platform ${FREGO_PLUGIN_TARGETS})
frego_warnings(fregod)
frego_version(fregod)
